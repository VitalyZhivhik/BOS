"""
Correlation engine for matching vulnerabilities with CVE/CWE/CAPEC/MITRE databases.
"""

from typing import List, Dict, Any
from datetime import datetime
from shared.models import ServerInfrastructure, AttackVector, Vulnerability, SecurityReport


class CorrelationEngine:
    """Движок корреляции уязвимостей с базами данных."""

    def __init__(self):
        self.cve_database = {}
        self.cwe_database = {}
        self.capec_database = {}
        self.mitre_database = {}

    def correlate_vulnerabilities(self, server_info: ServerInfrastructure, attack_vectors: List[AttackVector]) -> List[Vulnerability]:
        """Сопоставление уязвимостей с инфраструктурой сервера."""
        vulnerabilities = []
        
        # Simulated vulnerabilities based on server configuration
        if server_info.has_web_server:
            vulnerabilities.append(Vulnerability(
                cve_id="CVE-2023-1234",
                cwe_id="CWE-89",
                title="SQL Injection in Web Application",
                description="Potential SQL injection vulnerability detected",
                severity='high',
                cvss_score=7.5,
                affected_software=['nginx', 'apache']
            ))
        
        if server_info.has_database:
            vulnerabilities.append(Vulnerability(
                cve_id="CVE-2023-5678",
                cwe_id="CWE-287",
                title="Weak Database Authentication",
                description="Database accepts weak passwords",
                severity='critical',
                cvss_score=9.0,
                affected_software=['mysql', 'postgresql']
            ))
        
        # Mark attack vectors as realizable or not based on infrastructure
        for av in attack_vectors:
            if 'SQL' in av.name and not server_info.has_database:
                av.is_realizable = False
                av.realizability_reason = "No database software detected on server"
            elif 'HTTP' in av.name or 'Web' in av.name:
                if not server_info.has_web_server:
                    av.is_realizable = False
                    av.realizability_reason = "No web server detected on server"
                else:
                    av.is_realizable = True
        
        return vulnerabilities

    def generate_security_report(self, server_info: ServerInfrastructure, 
                                  vulnerabilities: List[Vulnerability],
                                  attack_vectors: List[AttackVector]) -> SecurityReport:
        """Генерация отчёта о безопасности."""
        
        realizable = [av for av in attack_vectors if av.is_realizable]
        non_realizable = [av for av in attack_vectors if not av.is_realizable]
        
        critical_count = sum(1 for v in vulnerabilities if v.severity == 'critical')
        high_count = sum(1 for v in vulnerabilities if v.severity == 'high')
        medium_count = sum(1 for v in vulnerabilities if v.severity == 'medium')
        low_count = sum(1 for v in vulnerabilities if v.severity == 'low')
        
        recommendations = []
        
        if server_info.has_database:
            recommendations.append({
                'title': 'Secure Database Configuration',
                'priority': 'High',
                'description': 'Ensure database is properly configured with strong authentication',
                'implementation_steps': '1. Change default passwords\n2. Enable SSL/TLS\n3. Restrict network access',
                'related_cves': ['CVE-2023-5678']
            })
        
        if not server_info.security_measures.get('firewall_active'):
            recommendations.append({
                'title': 'Enable Firewall',
                'priority': 'Critical',
                'description': 'No active firewall detected',
                'implementation_steps': '1. Install ufw or firewalld\n2. Configure rules\n3. Enable service',
                'related_cves': []
            })
        
        report = SecurityReport(
            report_id=f"RPT-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            generated_at=datetime.now(),
            server_infrastructure=server_info,
            scan_results=None,  # Would come from client
            total_vulnerabilities=len(vulnerabilities),
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            realizable_attacks=len(realizable),
            non_realizable_attacks=len(non_realizable),
            recommendations=recommendations
        )
        
        return report
