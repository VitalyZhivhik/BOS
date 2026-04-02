"""
Correlation engine that cross-references CVE, CWE, CAPEC, and MITRE ATT&CK databases.
"""

from typing import List, Dict, Any, Optional, Set
from datetime import datetime

from shared import (
    Vulnerability,
    AttackVector,
    AttackAssessment,
    AttackFeasibility,
    ServerInfrastructure,
    ScanResult,
    SecurityReport,
    SoftwareInfo,
    logger,
)


class CorrelationEngine:
    """Движок корреляции для сопоставления уязвимостей и атак."""

    def __init__(self):
        self.cve_database = self._load_cve_database()
        self.cwe_database = self._load_cwe_database()
        self.capec_database = self._load_capec_database()
        self.mitre_attack_database = self._load_mitre_attack_database()

    def _load_cve_database(self) -> Dict[str, Dict[str, Any]]:
        """
        Загрузка базы данных CVE.
        В реальной системе это будет подключено к API или локальной БД.
        """
        # Пример структуры - в продакшене загружается из базы данных
        return {
            "CVE-2021-44228": {
                "title": "Log4Shell",
                "description": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints",
                "severity": "critical",
                "cvss_score": 10.0,
                "cwe_id": "CWE-502",
                "capec_ids": ["CAPEC-484"],
                "affected_products": ["log4j", "java"],
                "mitre_technique": "T1190",
            },
            "CVE-2017-0144": {
                "title": "EternalBlue",
                "description": "SMBv1 vulnerability allowing remote code execution",
                "severity": "critical",
                "cvss_score": 9.3,
                "cwe_id": "CWE-119",
                "capec_ids": ["CAPEC-176"],
                "affected_products": ["smb", "windows"],
                "mitre_technique": "T1210",
            },
            "CVE-2019-11043": {
                "title": "PHP-FPM Remote Code Execution",
                "description": "Buffer underflow in PHP-FPM allows remote code execution",
                "severity": "high",
                "cvss_score": 9.1,
                "cwe_id": "CWE-119",
                "capec_ids": ["CAPEC-130"],
                "affected_products": ["php", "nginx", "apache"],
                "mitre_technique": "T1190",
            },
        }

    def _load_cwe_database(self) -> Dict[str, Dict[str, Any]]:
        """
        Загрузка базы данных CWE.
        """
        return {
            "CWE-89": {
                "name": "SQL Injection",
                "description": "Constructing SQL statements from untrusted input",
                "mitigations": [
                    "Use parameterized queries",
                    "Input validation",
                    "Web Application Firewall"
                ],
            },
            "CWE-79": {
                "name": "Cross-site Scripting (XSS)",
                "description": "Improper neutralization of input during web page generation",
                "mitigations": [
                    "Output encoding",
                    "Content Security Policy",
                    "Input validation"
                ],
            },
            "CWE-119": {
                "name": "Buffer Overflow",
                "description": "Improper restriction of operations within buffer bounds",
                "mitigations": [
                    "Bounds checking",
                    "Safe libraries",
                    "ASLR",
                    "DEP/NX"
                ],
            },
            "CWE-502": {
                "name": "Deserialization of Untrusted Data",
                "description": "Deserializing untrusted data without verification",
                "mitigations": [
                    "Avoid deserialization",
                    "Integrity checks",
                    "Input validation"
                ],
            },
            "CWE-287": {
                "name": "Improper Authentication",
                "description": "Failure to properly authenticate users",
                "mitigations": [
                    "Multi-factor authentication",
                    "Strong password policies",
                    "Account lockout"
                ],
            },
        }

    def _load_capec_database(self) -> Dict[str, Dict[str, Any]]:
        """
        Загрузка базы данных CAPEC.
        """
        return {
            "CAPEC-66": {
                "name": "SQL Injection",
                "description": "Injecting SQL commands through input vectors",
                "related_weaknesses": ["CWE-89"],
                "mitre_attack": ["T1190"],
            },
            "CAPEC-484": {
                "name": "Exploiting Deserialization Vulnerability",
                "description": "Exploiting insecure deserialization",
                "related_weaknesses": ["CWE-502"],
                "mitre_attack": ["T1190"],
            },
            "CAPEC-176": {
                "name": "Buffer Overflow via Parameter Expansion",
                "description": "Exploiting buffer overflow vulnerabilities",
                "related_weaknesses": ["CWE-119"],
                "mitre_attack": ["T1210", "T1190"],
            },
            "CAPEC-130": {
                "name": "Buffer Underread",
                "description": "Reading before the start of buffer",
                "related_weaknesses": ["CWE-119"],
                "mitre_attack": ["T1190"],
            },
            "CAPEC-111": {
                "name": "Brute Force",
                "description": "Trial and error to guess credentials",
                "related_weaknesses": ["CWE-287"],
                "mitre_attack": ["T1110"],
            },
        }

    def _load_mitre_attack_database(self) -> Dict[str, Dict[str, Any]]:
        """
        Загрузка базы данных MITRE ATT&CK.
        """
        return {
            "T1190": {
                "name": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
                "description": "Exploiting vulnerabilities in public-facing applications",
                "mitigations": [
                    "Keep software updated",
                    "Web Application Firewall",
                    "Network segmentation"
                ],
            },
            "T1110": {
                "name": "Brute Force",
                "tactic": "Credential Access",
                "description": "Attempting to obtain credentials through guessing",
                "mitigations": [
                    "Account lockout policies",
                    "Multi-factor authentication",
                    "Password complexity requirements"
                ],
            },
            "T1210": {
                "name": "Exploitation of Remote Services",
                "tactic": "Lateral Movement",
                "description": "Exploiting vulnerabilities in remote services",
                "mitigations": [
                    "Patch management",
                    "Network segmentation",
                    "Intrusion detection"
                ],
            },
            "T1078": {
                "name": "Valid Accounts",
                "tactic": "Persistence",
                "description": "Using legitimate credentials for access",
                "mitigations": [
                    "Privileged access management",
                    "User behavior analytics",
                    "Least privilege"
                ],
            },
            "T1021": {
                "name": "Remote Services",
                "tactic": "Lateral Movement",
                "description": "Using remote services for lateral movement",
                "mitigations": [
                    "Network segmentation",
                    "Disable unnecessary services",
                    "Monitor remote access"
                ],
            },
        }

    def assess_attack_feasibility(
        self,
        attack_vector: AttackVector,
        infrastructure: ServerInfrastructure,
        scan_result: ScanResult,
    ) -> AttackAssessment:
        """
        Оценка реализуемости атаки на основе инфраструктуры сервера.
        """
        feasibility = AttackFeasibility.FEASIBLE
        reasons = []
        affected_components = []
        remediation_steps = []

        # Проверка необходимых условий
        for condition in attack_vector.required_conditions:
            if condition == "database" and not infrastructure.has_database:
                feasibility = AttackFeasibility.INFEASIBLE
                reasons.append(f"Server has no database installed (required for {attack_vector.name})")
            
            elif condition == "web_server" and not infrastructure.has_web_server:
                feasibility = AttackFeasibility.INFEASIBLE
                reasons.append(f"Server has no web server installed (required for {attack_vector.name})")
            
            elif condition == "ssh_enabled":
                ssh_ports = [p for p in scan_result.open_ports if p.port == 22]
                if not ssh_ports:
                    feasibility = AttackFeasibility.INFEASIBLE
                    reasons.append("SSH service is not running")
                else:
                    affected_components.append("SSH")
            
            elif condition == "ftp_enabled":
                ftp_ports = [p for p in scan_result.open_ports if p.port == 21]
                if not ftp_ports:
                    feasibility = AttackFeasibility.INFEASIBLE
                    reasons.append("FTP service is not running")
                else:
                    affected_components.append("FTP")
            
            elif condition == "rdp_enabled":
                rdp_ports = [p for p in scan_result.open_ports if p.port == 3389]
                if not rdp_ports:
                    feasibility = AttackFeasibility.INFEASIBLE
                    reasons.append("RDP service is not running")
                else:
                    affected_components.append("RDP")
            
            elif condition == "mongodb_enabled":
                mongo_ports = [p for p in scan_result.open_ports if p.port == 27017]
                if not mongo_ports:
                    feasibility = AttackFeasibility.INFEASIBLE
                    reasons.append("MongoDB service is not running")
                else:
                    affected_components.append("MongoDB")
            
            elif condition == "smb_enabled":
                smb_ports = [p for p in scan_result.open_ports if p.port in [445, 139]]
                if not smb_ports:
                    feasibility = AttackFeasibility.INFEASIBLE
                    reasons.append("SMB service is not running")
                else:
                    affected_components.append("SMB")
            
            elif condition == "dns_enabled":
                dns_ports = [p for p in scan_result.open_ports if p.port == 53]
                if not dns_ports:
                    feasibility = AttackFeasibility.INFEASIBLE
                    reasons.append("DNS service is not running")
                else:
                    affected_components.append("DNS")
            
            elif condition == "vnc_enabled":
                vnc_ports = [p for p in scan_result.open_ports if p.port == 5900]
                if not vnc_ports:
                    feasibility = AttackFeasibility.INFEASIBLE
                    reasons.append("VNC service is not running")
                else:
                    affected_components.append("VNC")
            
            elif condition == "telnet_enabled":
                telnet_ports = [p for p in scan_result.open_ports if p.port == 23]
                if not telnet_ports:
                    feasibility = AttackFeasibility.INFEASIBLE
                    reasons.append("Telnet service is not running")
                else:
                    affected_components.append("Telnet")

        # Получение рекомендаций по устранению
        if attack_vector.mitre_technique_id:
            mitre_data = self.mitre_attack_database.get(attack_vector.mitre_technique_id, {})
            remediation_steps = mitre_data.get("mitigations", [])

        # Добавление общих рекомендаций
        if feasibility == AttackFeasibility.FEASIBLE:
            if not remediation_steps:
                remediation_steps = [
                    "Update all software to latest versions",
                    "Implement network segmentation",
                    "Enable logging and monitoring",
                    "Conduct regular security assessments",
                ]

        reason_str = "; ".join(reasons) if reasons else "All conditions met for attack"

        # Определение приоритета
        priority = self._calculate_priority(
            attack_vector,
            feasibility,
            len(scan_result.open_ports),
        )

        return AttackAssessment(
            attack_vector=attack_vector,
            feasibility=feasibility,
            reason=reason_str,
            affected_components=affected_components,
            remediation_steps=remediation_steps,
            priority=priority,
        )

    def _calculate_priority(
        self,
        attack_vector: AttackVector,
        feasibility: AttackFeasibility,
        open_ports_count: int,
    ) -> int:
        """Расчёт приоритета атаки (1 - наивысший)."""
        if feasibility == AttackFeasibility.INFEASIBLE:
            return 5  # Lowest priority

        # Базовый приоритет
        priority = 3

        # Повышение приоритета для критических тактик
        critical_tactics = ["Initial Access", "Credential Access", "Execution"]
        if attack_vector.mitre_tactic in critical_tactics:
            priority -= 1

        # Повышение приоритета при большом количестве открытых портов
        if open_ports_count > 5:
            priority -= 1

        return max(1, priority)

    def correlate_and_assess(
        self,
        infrastructure: ServerInfrastructure,
        scan_result: ScanResult,
    ) -> SecurityReport:
        """
        Полная корреляция данных и оценка всех векторов атак.
        """
        logger.info("Starting correlation and assessment")

        assessments = []
        
        for attack_vector in scan_result.attack_vectors:
            assessment = self.assess_attack_feasibility(
                attack_vector,
                infrastructure,
                scan_result,
            )
            assessments.append(assessment)

        # Разделение на реализуемые и нереализуемые атаки
        feasible_attacks = [a for a in assessments if a.feasibility == AttackFeasibility.FEASIBLE]
        infeasible_attacks = [a for a in assessments if a.feasibility == AttackFeasibility.INFEASIBLE]

        # Сортировка по приоритету
        feasible_attacks.sort(key=lambda x: x.priority)

        # Генерация рекомендаций
        remediation_recommendations = self._generate_remediation_recommendations(
            feasible_attacks,
            infrastructure,
        )

        # Создание отчёта
        report = SecurityReport(
            report_id=f"RPT-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            generated_at=datetime.now(),
            server_infrastructure=infrastructure,
            scan_results=scan_result,
            attack_assessments=assessments,
            feasible_attacks=feasible_attacks,
            infeasible_attacks=infeasible_attacks,
            remediation_recommendations=remediation_recommendations,
            summary=self._generate_summary(feasible_attacks, infeasible_attacks),
        )

        logger.info(f"Assessment complete. Feasible: {len(feasible_attacks)}, "
                   f"Infeasible: {len(infeasible_attacks)}")

        return report

    def _generate_remediation_recommendations(
        self,
        feasible_attacks: List[AttackAssessment],
        infrastructure: ServerInfrastructure,
    ) -> List[str]:
        """Генерация рекомендаций по устранению уязвимостей."""
        recommendations = set()

        for assessment in feasible_attacks:
            for step in assessment.remediation_steps:
                recommendations.add(step)

        # Добавление специфичных рекомендаций на основе инфраструктуры
        if infrastructure.has_web_server:
            recommendations.add("Deploy Web Application Firewall (WAF)")
            recommendations.add("Enable HTTPS with strong TLS configuration")

        if infrastructure.security_tools:
            recommendations.add("Review and update security tool configurations")
        else:
            recommendations.add("Install firewall and intrusion detection system")

        if not any(t.type == "firewall" for t in infrastructure.security_tools):
            recommendations.add("Configure host-based firewall (iptables/ufw)")

        return list(recommendations)

    def _generate_summary(
        self,
        feasible_attacks: List[AttackAssessment],
        infeasible_attacks: List[AttackAssessment],
    ) -> str:
        """Генерация краткого резюме отчёта."""
        summary_parts = []

        if feasible_attacks:
            summary_parts.append(
                f"Found {len(feasible_attacks)} feasible attack(s) requiring immediate attention."
            )
            high_priority = [a for a in feasible_attacks if a.priority <= 2]
            if high_priority:
                summary_parts.append(
                    f"{len(high_priority)} attack(s) are high priority."
                )
        else:
            summary_parts.append("No feasible attacks identified.")

        if infeasible_attacks:
            summary_parts.append(
                f"{len(infeasible_attacks)} attack(s) are not feasible due to system configuration."
            )

        return " ".join(summary_parts)


def main():
    """Точка входа для демонстрации корреляционного движка."""
    # Пример использования
    engine = CorrelationEngine()
    
    print("Correlation Engine initialized")
    print(f"CVE entries: {len(engine.cve_database)}")
    print(f"CWE entries: {len(engine.cwe_database)}")
    print(f"CAPEC entries: {len(engine.capec_database)}")
    print(f"MITRE ATT&CK entries: {len(engine.mitre_attack_database)}")


if __name__ == "__main__":
    main()
