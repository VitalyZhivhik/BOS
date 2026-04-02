"""
Client-side port scanner and attack vector identification.
"""

import socket
import subprocess
from typing import List, Dict, Any, Optional
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from shared import (
    OpenPort,
    ScanResult,
    AttackVector,
    Vulnerability,
    logger,
)


class PortScanner:
    """Сканер портов для обнаружения открытых служб."""

    def __init__(self, target_ip: str, timeout: float = 1.0):
        self.target_ip = target_ip
        self.timeout = timeout
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
            993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 27017
        ]

    def scan_port(self, port: int, protocol: str = "tcp") -> Optional[OpenPort]:
        """Сканирование одного порта."""
        try:
            if protocol == "tcp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target_ip, port))

            if result == 0:
                service = self._identify_service(port, protocol)
                version = self._get_service_version(port, protocol)
                
                return OpenPort(
                    port=port,
                    protocol=protocol,
                    service=service,
                    version=version,
                    state="open"
                )

            sock.close()
        except (socket.timeout, socket.error, OSError) as e:
            logger.debug(f"Error scanning port {port}: {e}")

        return None

    def _identify_service(self, port: int, protocol: str) -> Optional[str]:
        """Идентификация службы по порту."""
        common_services = {
            21: "ftp",
            22: "ssh",
            23: "telnet",
            25: "smtp",
            53: "dns",
            80: "http",
            110: "pop3",
            111: "rpcbind",
            135: "msrpc",
            139: "netbios-ssn",
            143: "imap",
            443: "https",
            445: "microsoft-ds",
            993: "imaps",
            995: "pop3s",
            1723: "pptp",
            3306: "mysql",
            3389: "rdp",
            5900: "vnc",
            8080: "http-proxy",
            8443: "https-alt",
            27017: "mongodb",
        }

        return common_services.get(port)

    def _get_service_version(self, port: int, protocol: str) -> Optional[str]:
        """Получение версии службы (баннер)."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target_ip, port))

            # Try to get banner
            sock.send(b"\r\n")
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()

            sock.close()

            if banner:
                # Clean up banner
                banner = banner.replace('\x00', '').strip()
                return banner[:200]  # Limit length

        except (socket.timeout, socket.error, OSError):
            pass

        return None

    def scan_all_ports(self, ports: Optional[List[int]] = None) -> List[OpenPort]:
        """Сканирование всех указанных портов."""
        ports_to_scan = ports or self.common_ports
        open_ports = []

        logger.info(f"Starting port scan on {self.target_ip}")
        logger.info(f"Scanning {len(ports_to_scan)} ports")

        with ThreadPoolExecutor(max_workers=50) as executor:
            future_to_port = {
                executor.submit(self.scan_port, port): port
                for port in ports_to_scan
            }

            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    result = future.result()
                    if result:
                        open_ports.append(result)
                        logger.info(f"Port {port} is open ({result.service})")
                except Exception as e:
                    logger.error(f"Error processing port {port}: {e}")

        logger.info(f"Scan complete. Found {len(open_ports)} open ports")
        return open_ports


class AttackVectorIdentifier:
    """Идентификатор векторов атак на основе результатов сканирования."""

    def __init__(self):
        self.attack_vectors_db = self._load_attack_vectors()

    def _load_attack_vectors(self) -> List[Dict[str, Any]]:
        """Загрузка базы векторов атак."""
        return [
            {
                "id": "AV-001",
                "name": "SQL Injection",
                "description": "Injection of SQL code through web forms or URL parameters",
                "mitre_technique_id": "T1190",
                "mitre_tactic": "Initial Access",
                "required_conditions": ["web_server", "database"],
                "target_ports": [80, 443, 8080, 8443],
                "target_services": ["http", "https", "mysql", "postgresql"],
            },
            {
                "id": "AV-002",
                "name": "SSH Brute Force",
                "description": "Brute force attack on SSH service",
                "mitre_technique_id": "T1110",
                "mitre_tactic": "Credential Access",
                "required_conditions": ["ssh_enabled"],
                "target_ports": [22],
                "target_services": ["ssh"],
            },
            {
                "id": "AV-003",
                "name": "FTP Anonymous Access",
                "description": "Anonymous access to FTP server",
                "mitre_technique_id": "T1078",
                "mitre_tactic": "Initial Access",
                "required_conditions": ["ftp_enabled"],
                "target_ports": [21],
                "target_services": ["ftp"],
            },
            {
                "id": "AV-004",
                "name": "RDP Brute Force",
                "description": "Brute force attack on RDP service",
                "mitre_technique_id": "T1110",
                "mitre_tactic": "Credential Access",
                "required_conditions": ["rdp_enabled"],
                "target_ports": [3389],
                "target_services": ["rdp"],
            },
            {
                "id": "AV-005",
                "name": "MongoDB NoSQL Injection",
                "description": "NoSQL injection attack on MongoDB",
                "mitre_technique_id": "T1190",
                "mitre_tactic": "Initial Access",
                "required_conditions": ["mongodb_enabled"],
                "target_ports": [27017],
                "target_services": ["mongodb"],
            },
            {
                "id": "AV-006",
                "name": "SMB Exploitation",
                "description": "Exploitation of SMB vulnerabilities (EternalBlue, etc.)",
                "mitre_technique_id": "T1210",
                "mitre_tactic": "Lateral Movement",
                "required_conditions": ["smb_enabled"],
                "target_ports": [445, 139],
                "target_services": ["microsoft-ds", "netbios-ssn"],
            },
            {
                "id": "AV-007",
                "name": "DNS Zone Transfer",
                "description": "DNS zone transfer to enumerate internal hosts",
                "mitre_technique_id": "T1590",
                "mitre_tactic": "Reconnaissance",
                "required_conditions": ["dns_enabled"],
                "target_ports": [53],
                "target_services": ["dns"],
            },
            {
                "id": "AV-008",
                "name": "VNC Unauthorized Access",
                "description": "Unauthorized access to VNC service",
                "mitre_technique_id": "T1021",
                "mitre_tactic": "Lateral Movement",
                "required_conditions": ["vnc_enabled"],
                "target_ports": [5900],
                "target_services": ["vnc"],
            },
            {
                "id": "AV-009",
                "name": "Telnet Cleartext Attack",
                "description": "Intercepting cleartext credentials via Telnet",
                "mitre_technique_id": "T1040",
                "mitre_tactic": "Credential Access",
                "required_conditions": ["telnet_enabled"],
                "target_ports": [23],
                "target_services": ["telnet"],
            },
            {
                "id": "AV-010",
                "name": "HTTP Vulnerabilities",
                "description": "Various HTTP-based attacks (XSS, CSRF, etc.)",
                "mitre_technique_id": "T1189",
                "mitre_tactic": "Initial Access",
                "required_conditions": ["web_server"],
                "target_ports": [80, 443, 8080, 8443],
                "target_services": ["http", "https", "http-proxy"],
            },
        ]

    def identify_attack_vectors(self, open_ports: List[OpenPort]) -> List[AttackVector]:
        """Определение возможных векторов атак на основе открытых портов."""
        identified_vectors = []

        # Create set of open ports and services
        open_port_numbers = {p.port for p in open_ports}
        open_services = {p.service for p in open_ports if p.service}

        for vector_data in self.attack_vectors_db:
            # Check if any target port is open
            has_open_port = bool(set(vector_data["target_ports"]) & open_port_numbers)
            
            # Check if any target service is running
            has_target_service = bool(set(vector_data["target_services"]) & open_services)

            if has_open_port or has_target_service:
                vector = AttackVector(
                    id=vector_data["id"],
                    name=vector_data["name"],
                    description=vector_data["description"],
                    mitre_technique_id=vector_data.get("mitre_technique_id"),
                    mitre_tactic=vector_data.get("mitre_tactic"),
                    required_conditions=vector_data.get("required_conditions", []),
                    target_ports=vector_data.get("target_ports", []),
                    target_services=vector_data.get("target_services", []),
                )
                identified_vectors.append(vector)
                logger.info(f"Identified attack vector: {vector.name}")

        return identified_vectors


def perform_scan(target_ip: str) -> ScanResult:
    """Выполнение полного сканирования цели."""
    logger.info(f"Starting scan of {target_ip}")

    # Port scanning
    scanner = PortScanner(target_ip)
    open_ports = scanner.scan_all_ports()

    # Attack vector identification
    identifier = AttackVectorIdentifier()
    attack_vectors = identifier.identify_attack_vectors(open_ports)

    scan_result = ScanResult(
        timestamp=datetime.now(),
        target_ip=target_ip,
        open_ports=open_ports,
        attack_vectors=attack_vectors,
    )

    logger.info(f"Scan complete. Found {len(open_ports)} open ports, "
               f"{len(attack_vectors)} potential attack vectors")

    return scan_result


def main():
    """Точка входа для сканера."""
    import argparse

    parser = argparse.ArgumentParser(description="Port Scanner and Attack Vector Identifier")
    parser.add_argument("--target", "-t", required=True, help="Target IP address")
    parser.add_argument("--output", "-o", help="Output file (JSON)")
    args = parser.parse_args()

    result = perform_scan(args.target)

    print(f"\nScan Results for {args.target}")
    print("=" * 50)
    print(f"Timestamp: {result.timestamp}")
    print(f"Open Ports: {len(result.open_ports)}")
    
    for port in result.open_ports:
        print(f"  - Port {port.port}/{port.protocol}: {port.service} ({port.version or 'unknown'})")

    print(f"\nPotential Attack Vectors: {len(result.attack_vectors)}")
    for vector in result.attack_vectors:
        print(f"  - {vector.name} ({vector.id})")
        print(f"    MITRE: {vector.mitre_technique_id} - {vector.mitre_tactic}")

    if args.output:
        from shared import save_json
        save_json({
            "timestamp": result.timestamp.isoformat(),
            "target_ip": result.target_ip,
            "open_ports": [
                {"port": p.port, "protocol": p.protocol, "service": p.service}
                for p in result.open_ports
            ],
            "attack_vectors": [
                {"id": v.id, "name": v.name, "mitre_id": v.mitre_technique_id}
                for v in result.attack_vectors
            ],
        }, args.output)
        print(f"\nResults saved to {args.output}")

    return result


if __name__ == "__main__":
    main()
