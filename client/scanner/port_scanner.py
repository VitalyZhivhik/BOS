"""
Port scanner for identifying open ports and services.
"""

import socket
from typing import List, Dict, Any, Callable, Optional
from datetime import datetime
from shared.models import ScanResult, AttackVector


class PortScanner:
    """Сканер портов для обнаружения открытых портов и служб."""

    def __init__(self):
        self.scan_running = False
        self.common_ports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 993: 'IMAPS',
            995: 'POP3S', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
            6379: 'Redis', 8080: 'HTTP-Proxy', 27017: 'MongoDB'
        }

    def scan(self, target: str, port_start: int = 1, port_end: int = 1000,
             scan_type: str = 'tcp', callback: Optional[Callable] = None) -> ScanResult:
        """Сканирование портов цели."""
        self.scan_running = True
        open_ports = []
        services = []
        scanned = 0
        closed = 0
        filtered = 0

        for port in range(port_start, min(port_end + 1, 1001)):
            if not self.scan_running:
                break

            result = self._scan_port(target, port, scan_type)
            scanned += 1

            if result['state'] == 'open':
                open_ports.append(result)
                services.append({
                    'name': result.get('service', 'unknown'),
                    'port': port,
                    'protocol': result['protocol']
                })
            elif result['state'] == 'filtered':
                filtered += 1
            else:
                closed += 1

            if callback:
                callback(scanned, len(open_ports), filtered, closed)

        return ScanResult(
            timestamp=datetime.now(),
            target_ip=target,
            open_ports=open_ports,
            identified_services=services,
            attack_vectors=[]
        )

    def _scan_port(self, target: str, port: int, scan_type: str) -> Dict[str, Any]:
        """Сканирование одного порта."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            sock.close()

            if result == 0:
                service = self.common_ports.get(port, 'unknown')
                return {
                    'port': port,
                    'protocol': 'TCP',
                    'state': 'open',
                    'service': service
                }
            else:
                return {'port': port, 'protocol': 'TCP', 'state': 'closed'}

        except socket.timeout:
            return {'port': port, 'protocol': 'TCP', 'state': 'filtered'}
        except Exception:
            return {'port': port, 'protocol': 'TCP', 'state': 'closed'}

    def stop_scan(self):
        """Остановка сканирования."""
        self.scan_running = False

    def identify_attack_vectors(self, scan_result: ScanResult) -> List[AttackVector]:
        """Идентификация векторов атак на основе результатов сканирования."""
        attack_vectors = []
        vector_id = 1

        attack_patterns = {
            'SSH': {
                'name': 'SSH Brute Force',
                'mitre': 'T1110',
                'capec': 'CAPEC-49',
                'description': 'Brute force attack on SSH service'
            },
            'FTP': {
                'name': 'FTP Anonymous Login',
                'mitre': 'T1078',
                'capec': 'CAPEC-57',
                'description': 'Anonymous FTP access attempt'
            },
            'HTTP': {
                'name': 'HTTP Vulnerabilities',
                'mitre': 'T1190',
                'capec': 'CAPEC-1',
                'description': 'Web application attacks including XSS, SQLi'
            },
            'MySQL': {
                'name': 'SQL Injection',
                'mitre': 'T1190',
                'capec': 'CAPEC-66',
                'description': 'SQL injection attacks on database'
            },
            'RDP': {
                'name': 'RDP Brute Force',
                'mitre': 'T1110',
                'capec': 'CAPEC-49',
                'description': 'Brute force attack on RDP service'
            },
            'MongoDB': {
                'name': 'MongoDB Unauthorized Access',
                'mitre': 'T1190',
                'capec': 'CAPEC-560',
                'description': 'Unauthorized access to MongoDB instance'
            },
            'Redis': {
                'name': 'Redis Unauthorized Access',
                'mitre': 'T1190',
                'capec': 'CAPEC-560',
                'description': 'Unauthorized access to Redis instance'
            }
        }

        for port_info in scan_result.open_ports:
            service = port_info.get('service', 'unknown')
            
            if service in attack_patterns:
                pattern = attack_patterns[service]
                av = AttackVector(
                    id=f"AV{vector_id:03d}",
                    name=pattern['name'],
                    description=pattern['description'],
                    port=port_info['port'],
                    protocol=port_info['protocol'],
                    mitre_technique=pattern['mitre'],
                    capec_id=pattern['capec'],
                    is_realizable=True
                )
                attack_vectors.append(av)
                vector_id += 1

        scan_result.attack_vectors = attack_vectors
        return attack_vectors
