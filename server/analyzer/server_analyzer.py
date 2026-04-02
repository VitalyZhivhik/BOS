"""
Server-side analyzer - analyzes installed software, security tools, and infrastructure.
"""

import socket
import subprocess
import platform
from typing import List, Dict, Any, Optional
from pathlib import Path

from shared import (
    SoftwareInfo,
    SecurityTool,
    ServerInfrastructure,
    OpenPort,
    logger,
)


class ServerAnalyzer:
    """Анализатор сервера для определения установленного ПО и средств защиты."""

    def __init__(self):
        self.hostname = socket.gethostname()
        self.os_type = platform.system()
        self.os_version = platform.version()

    def get_installed_software(self) -> List[SoftwareInfo]:
        """Получение списка установленного ПО."""
        software_list = []

        if self.os_type == "Linux":
            software_list.extend(self._get_linux_software())
        elif self.os_type == "Windows":
            software_list.extend(self._get_windows_software())

        return software_list

    def _get_linux_software(self) -> List[SoftwareInfo]:
        """Получение списка ПО для Linux."""
        software_list = []

        # Try dpkg for Debian-based systems
        try:
            result = subprocess.run(
                ["dpkg", "--list"],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0:
                packages = self._parse_dpkg_output(result.stdout)
                software_list.extend(packages)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            logger.debug("dpkg not available or timed out")

        # Try rpm for Red Hat-based systems
        try:
            result = subprocess.run(
                ["rpm", "-qa", "--qf", "%{NAME}|%{VERSION}|%{VENDOR}|%{INSTALLPREFIX}"],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0:
                packages = self._parse_rpm_output(result.stdout)
                software_list.extend(packages)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            logger.debug("rpm not available or timed out")

        # Check for common services
        common_services = {
            "nginx": ("web_server", "/usr/sbin/nginx"),
            "apache2": ("web_server", "/usr/sbin/apache2"),
            "httpd": ("web_server", "/usr/sbin/httpd"),
            "mysql": ("database", "/usr/sbin/mysqld"),
            "postgresql": ("database", "/usr/lib/postgresql"),
            "mongodb": ("database", "/usr/bin/mongod"),
            "redis": ("database", "/usr/bin/redis-server"),
            "ssh": ("service", "/usr/sbin/sshd"),
            "docker": ("container", "/usr/bin/docker"),
            "kubernetes": ("container", "/usr/bin/kubelet"),
        }

        for name, (category, path) in common_services.items():
            if Path(path).exists():
                version = self._get_service_version(name)
                software_list.append(SoftwareInfo(
                    name=name,
                    version=version or "unknown",
                    vendor=None,
                    install_path=path,
                    category=category
                ))

        return software_list

    def _get_windows_software(self) -> List[SoftwareInfo]:
        """Получение списка ПО для Windows."""
        software_list = []
        
        try:
            import winreg
            
            registry_paths = [
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            ]
            
            for reg_path in registry_paths:
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path)
                    # Implementation would continue here
                    winreg.CloseKey(key)
                except (FileNotFoundError, WindowsError):
                    continue
        except ImportError:
            logger.debug("Windows registry access not available")

        return software_list

    def _parse_dpkg_output(self, output: str) -> List[SoftwareInfo]:
        """Парсинг вывода dpkg --list."""
        packages = []
        for line in output.split('\n'):
            if line.startswith('ii'):
                parts = line.split()
                if len(parts) >= 3:
                    name = parts[1].split(':')[0]  # Remove architecture suffix
                    version = parts[2]
                    packages.append(SoftwareInfo(
                        name=name,
                        version=version,
                        category=self._categorize_package(name)
                    ))
        return packages

    def _parse_rpm_output(self, output: str) -> List[SoftwareInfo]:
        """Парсинг вывода rpm -qa."""
        packages = []
        for line in output.split('\n'):
            if line.strip():
                parts = line.split('|')
                if len(parts) >= 2:
                    packages.append(SoftwareInfo(
                        name=parts[0],
                        version=parts[1],
                        vendor=parts[2] if len(parts) > 2 else None,
                        install_path=parts[3] if len(parts) > 3 else None,
                        category=self._categorize_package(parts[0])
                    ))
        return packages

    def _categorize_package(self, name: str) -> Optional[str]:
        """Категоризация пакета."""
        database_packages = ['mysql', 'postgresql', 'mariadb', 'mongodb', 'redis', 'sqlite']
        web_server_packages = ['nginx', 'apache', 'httpd', 'lighttpd', 'iis']
        security_packages = ['fail2ban', 'ufw', 'iptables', 'firewalld', 'selinux', 'apparmor']
        container_packages = ['docker', 'kubernetes', 'podman', 'containerd']

        name_lower = name.lower()
        
        if any(db in name_lower for db in database_packages):
            return "database"
        elif any(web in name_lower for web in web_server_packages):
            return "web_server"
        elif any(sec in name_lower for sec in security_packages):
            return "security"
        elif any(cont in name_lower for cont in container_packages):
            return "container"
        
        return None

    def _get_service_version(self, service_name: str) -> Optional[str]:
        """Получение версии службы."""
        try:
            result = subprocess.run(
                [service_name, "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                # Extract version from first line
                first_line = result.stdout.split('\n')[0]
                return first_line[:100]  # Limit length
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        return None

    def detect_security_tools(self) -> List[SecurityTool]:
        """Обнаружение средств безопасности."""
        security_tools = []

        # Check for firewalls
        if self.os_type == "Linux":
            # Check iptables
            try:
                result = subprocess.run(
                    ["iptables", "-L", "-n"],
                    capture_output=True,
                    timeout=10
                )
                if result.returncode == 0:
                    security_tools.append(SecurityTool(
                        name="iptables",
                        type="firewall",
                        status="active"
                    ))
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

            # Check ufw
            try:
                result = subprocess.run(
                    ["ufw", "status"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0 and "active" in result.stdout.lower():
                    security_tools.append(SecurityTool(
                        name="ufw",
                        type="firewall",
                        status="active"
                    ))
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

            # Check fail2ban
            try:
                result = subprocess.run(
                    ["systemctl", "is-active", "fail2ban"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.stdout.strip() == "active":
                    security_tools.append(SecurityTool(
                        name="fail2ban",
                        type="ids",
                        status="active"
                    ))
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

        return security_tools

    def analyze_infrastructure(self) -> ServerInfrastructure:
        """Полный анализ инфраструктуры сервера."""
        logger.info(f"Starting infrastructure analysis for {self.hostname}")

        software = self.get_installed_software()
        security_tools = self.detect_security_tools()

        # Determine infrastructure characteristics
        has_database = any(s.category == "database" for s in software)
        has_web_server = any(s.category == "web_server" for s in software)
        has_file_sharing = any(s.name in ['samba', 'nfs', 'ftp'] for s in software)

        infrastructure = ServerInfrastructure(
            hostname=self.hostname,
            os_type=self.os_type,
            os_version=self.os_version,
            installed_software=software,
            security_tools=security_tools,
            has_database=has_database,
            has_web_server=has_web_server,
            has_file_sharing=has_file_sharing
        )

        logger.info(f"Analysis complete. Found {len(software)} software packages, "
                   f"{len(security_tools)} security tools")
        
        return infrastructure


def main():
    """Точка входа для анализа сервера."""
    analyzer = ServerAnalyzer()
    infrastructure = analyzer.analyze_infrastructure()
    
    print(f"Hostname: {infrastructure.hostname}")
    print(f"OS: {infrastructure.os_type} {infrastructure.os_version}")
    print(f"Installed software: {len(infrastructure.installed_software)} packages")
    print(f"Security tools: {len(infrastructure.security_tools)} detected")
    print(f"Has database: {infrastructure.has_database}")
    print(f"Has web server: {infrastructure.has_web_server}")
    
    return infrastructure


if __name__ == "__main__":
    main()
