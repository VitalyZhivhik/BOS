"""
Server-side analyzer - analyzes installed software, security tools, and infrastructure.
"""

import socket
import subprocess
import platform
from typing import List, Dict, Any, Optional
from pathlib import Path

from shared.models import ServerInfrastructure


class ServerAnalyzer:
    """Анализатор сервера для определения установленного ПО и средств защиты."""

    def __init__(self):
        self.hostname = socket.gethostname()
        self.os_type = platform.system()
        self.os_version = platform.version()
        self.kernel_version = platform.release()
        self.architecture = platform.machine()

    def analyze_server(self) -> ServerInfrastructure:
        """Полный анализ инфраструктуры сервера."""
        software = self.get_installed_software()
        security_measures = self.detect_security_measures()
        infrastructure_data = self.detect_infrastructure()
        open_ports = self.get_open_ports()

        has_database = any('database' in str(s).lower() for s in software) or \
                       any(db in infrastructure_data.get('databases', []) for db in ['mysql', 'postgresql', 'mongodb'])
        has_web_server = any('web' in str(s).lower() for s in software) or \
                        any(ws in infrastructure_data.get('web_servers', []) for ws in ['nginx', 'apache', 'httpd'])

        return ServerInfrastructure(
            hostname=self.hostname,
            os_type=self.os_type,
            os_version=self.os_version,
            kernel_version=self.kernel_version,
            architecture=self.architecture,
            installed_software=software,
            security_measures=security_measures,
            infrastructure=infrastructure_data,
            open_ports=open_ports,
            has_database=has_database,
            has_web_server=has_web_server,
            has_file_sharing=False
        )

    def get_installed_software(self) -> List[Dict[str, Any]]:
        """Получение списка установленного ПО."""
        software_list = []

        if self.os_type == "Linux":
            software_list.extend(self._get_linux_software())
        elif self.os_type == "Windows":
            software_list.extend(self._get_windows_software())

        return software_list

    def _get_linux_software(self) -> List[Dict[str, Any]]:
        """Получение списка ПО для Linux."""
        software_list = []

        try:
            result = subprocess.run(["dpkg", "--list"], capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                packages = self._parse_dpkg_output(result.stdout)
                software_list.extend(packages)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        common_services = {
            "nginx": ("web_server", "/usr/sbin/nginx"),
            "apache2": ("web_server", "/usr/sbin/apache2"),
            "mysql": ("database", "/usr/sbin/mysqld"),
            "postgresql": ("database", "/usr/lib/postgresql"),
            "mongodb": ("database", "/usr/bin/mongod"),
            "redis": ("database", "/usr/bin/redis-server"),
            "docker": ("container", "/usr/bin/docker"),
        }

        for name, (category, path) in common_services.items():
            if Path(path).exists():
                version = self._get_service_version(name)
                software_list.append({'name': name, 'version': version or "unknown", 'category': category})

        return software_list

    def _get_windows_software(self) -> List[Dict[str, Any]]:
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
                    i = 0
                    while True:
                        try:
                            subkey_name = winreg.EnumKey(key, i)
                            subkey = winreg.OpenKey(key, subkey_name)
                            try:
                                display_name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                                display_version = winreg.QueryValueEx(subkey, "DisplayVersion")[0]
                                software_list.append({'name': display_name, 'version': display_version, 'category': None})
                            except (FileNotFoundError, WindowsError):
                                pass
                            winreg.CloseKey(subkey)
                        except OSError:
                            break
                        i += 1
                    winreg.CloseKey(key)
                except (FileNotFoundError, WindowsError):
                    continue
        except ImportError:
            pass
        return software_list

    def _parse_dpkg_output(self, output: str) -> List[Dict[str, Any]]:
        """Парсинг вывода dpkg --list."""
        packages = []
        for line in output.split('\n'):
            if line.startswith('ii'):
                parts = line.split()
                if len(parts) >= 3:
                    name = parts[1].split(':')[0]
                    version = parts[2]
                    packages.append({'name': name, 'version': version, 'category': self._categorize_package(name)})
        return packages[:50]

    def _categorize_package(self, name: str) -> Optional[str]:
        """Категоризация пакета."""
        database_packages = ['mysql', 'postgresql', 'mariadb', 'mongodb', 'redis']
        web_server_packages = ['nginx', 'apache', 'httpd']
        security_packages = ['fail2ban', 'ufw', 'iptables', 'firewalld']

        name_lower = name.lower()
        if any(db in name_lower for db in database_packages):
            return "database"
        elif any(web in name_lower for web in web_server_packages):
            return "web_server"
        elif any(sec in name_lower for sec in security_packages):
            return "security"
        return None

    def _get_service_version(self, service_name: str) -> Optional[str]:
        """Получение версии службы."""
        try:
            result = subprocess.run([service_name, "--version"], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                return result.stdout.split('\n')[0][:100]
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return None

    def detect_security_measures(self) -> Dict[str, Any]:
        """Обнаружение средств безопасности."""
        measures = {'firewall_active': False, 'firewall_type': None, 'selinux_status': 'unknown', 'fail2ban_active': False}

        if self.os_type == "Linux":
            try:
                result = subprocess.run(["iptables", "-L", "-n"], capture_output=True, timeout=10)
                if result.returncode == 0:
                    measures['firewall_active'] = True
                    measures['firewall_type'] = 'iptables'
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

            try:
                result = subprocess.run(["ufw", "status"], capture_output=True, text=True, timeout=10)
                if result.returncode == 0 and "active" in result.stdout.lower():
                    measures['firewall_active'] = True
                    measures['firewall_type'] = 'ufw'
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

            try:
                result = subprocess.run(["getenforce"], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    measures['selinux_status'] = result.stdout.strip()
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

            try:
                result = subprocess.run(["systemctl", "is-active", "fail2ban"], capture_output=True, text=True, timeout=10)
                if result.stdout.strip() == "active":
                    measures['fail2ban_active'] = True
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

        return measures

    def detect_infrastructure(self) -> Dict[str, Any]:
        """Обнаружение инфраструктуры."""
        infrastructure = {'databases': [], 'web_servers': [], 'file_shares': [], 'containers': []}

        db_services = {
            'mysql': ['/usr/sbin/mysqld', '/etc/mysql'],
            'postgresql': ['/usr/lib/postgresql', '/etc/postgresql'],
            'mongodb': ['/usr/bin/mongod', '/etc/mongodb'],
            'redis': ['/usr/bin/redis-server', '/etc/redis']
        }
        for db_name, paths in db_services.items():
            if any(Path(p).exists() for p in paths):
                infrastructure['databases'].append(db_name)

        web_services = {
            'nginx': ['/usr/sbin/nginx', '/etc/nginx'],
            'apache': ['/usr/sbin/apache2', '/etc/apache2'],
            'httpd': ['/usr/sbin/httpd', '/etc/httpd']
        }
        for web_name, paths in web_services.items():
            if any(Path(p).exists() for p in paths):
                infrastructure['web_servers'].append(web_name)

        return infrastructure

    def get_open_ports(self) -> List[Dict[str, Any]]:
        """Получение списка открытых портов."""
        open_ports = []
        try:
            if self.os_type == "Linux":
                for proto in ['tcp', 'udp']:
                    try:
                        with open(f'/proc/net/{proto}', 'r') as f:
                            lines = f.readlines()[1:]
                            for line in lines:
                                parts = line.split()
                                if len(parts) >= 4 and parts[3] == '0A':
                                    local_addr = parts[1]
                                    port_hex = local_addr.split(':')[1]
                                    port = int(port_hex, 16)
                                    open_ports.append({'port': port, 'protocol': proto.upper(), 'state': 'open'})
                    except (FileNotFoundError, IOError):
                        pass
        except Exception:
            pass
        return open_ports[:20]
