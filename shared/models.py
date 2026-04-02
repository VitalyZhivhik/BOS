"""
Shared models and data structures for the security analysis system.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from enum import Enum
from datetime import datetime


class AttackFeasibility(Enum):
    """Статус реализуемости атаки."""
    FEASIBLE = "feasible"  # Атака возможна
    INFEASIBLE = "infeasible"  # Атака невозможна
    PARTIAL = "partial"  # Атака частично возможна
    UNKNOWN = "unknown"  # Статус неизвестен


class Severity(Enum):
    """Уровень серьёзности уязвимости."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class SoftwareInfo:
    """Информация о установленном ПО."""
    name: str
    version: str
    vendor: Optional[str] = None
    install_path: Optional[str] = None
    category: Optional[str] = None  # e.g., "web_server", "database", "security"


@dataclass
class SecurityTool:
    """Информация о средстве безопасности."""
    name: str
    type: str  # e.g., "firewall", "antivirus", "ids", "siem"
    version: Optional[str] = None
    status: str = "active"  # active, inactive, misconfigured
    configuration: Optional[Dict[str, Any]] = None


@dataclass
class OpenPort:
    """Информация об открытом порте."""
    port: int
    protocol: str  # tcp, udp
    service: Optional[str] = None
    version: Optional[str] = None
    state: str = "open"


@dataclass
class Vulnerability:
    """Информация об уязвимости."""
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    capec_id: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Severity = Severity.MEDIUM
    cvss_score: Optional[float] = None
    affected_software: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)


@dataclass
class AttackVector:
    """Вектор атаки."""
    id: str
    name: str
    description: str
    mitre_technique_id: Optional[str] = None
    mitre_tactic: Optional[str] = None
    required_conditions: List[str] = field(default_factory=list)
    target_ports: List[int] = field(default_factory=list)
    target_services: List[str] = field(default_factory=list)
    associated_vulnerabilities: List[Vulnerability] = field(default_factory=list)


@dataclass
class AttackAssessment:
    """Оценка атаки."""
    attack_vector: AttackVector
    feasibility: AttackFeasibility
    reason: str
    affected_components: List[str] = field(default_factory=list)
    remediation_steps: List[str] = field(default_factory=list)
    priority: int = 0  # 1 - highest priority


@dataclass
class ServerInfrastructure:
    """Инфраструктура сервера."""
    hostname: str
    os_type: str
    os_version: str
    installed_software: List[SoftwareInfo] = field(default_factory=list)
    security_tools: List[SecurityTool] = field(default_factory=list)
    open_ports: List[OpenPort] = field(default_factory=list)
    running_services: List[str] = field(default_factory=list)
    has_database: bool = False
    has_web_server: bool = False
    has_file_sharing: bool = False
    network_zones: List[str] = field(default_factory=list)


@dataclass
class ScanResult:
    """Результат сканирования."""
    timestamp: datetime
    target_ip: str
    open_ports: List[OpenPort] = field(default_factory=list)
    identified_services: List[Dict[str, Any]] = field(default_factory=list)
    potential_vulnerabilities: List[Vulnerability] = field(default_factory=list)
    attack_vectors: List[AttackVector] = field(default_factory=list)


@dataclass
class SecurityReport:
    """Отчёт о безопасности."""
    report_id: str
    generated_at: datetime
    server_infrastructure: ServerInfrastructure
    scan_results: ScanResult
    attack_assessments: List[AttackAssessment] = field(default_factory=list)
    feasible_attacks: List[AttackAssessment] = field(default_factory=list)
    infeasible_attacks: List[AttackAssessment] = field(default_factory=list)
    remediation_recommendations: List[str] = field(default_factory=list)
    summary: Optional[str] = None
