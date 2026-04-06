#!/usr/bin/env python3
"""
ScanOval integration module for server-side vulnerability database processing.
This module handles communication with the ScanOval utility to retrieve and process
vulnerability data from OVAL definitions.
"""

import logging
import subprocess
import json
from typing import List, Dict, Any, Optional
from pathlib import Path
from datetime import datetime

from shared.models import Vulnerability, Severity

logger = logging.getLogger(__name__)


class ScanOvalIntegration:
    """Интеграция с утилитой ScanOval для получения данных об уязвимостях."""
    
    def __init__(self, oval_db_path: Optional[str] = None):
        """
        Инициализация интеграции с ScanOval.
        
        Args:
            oval_db_path: Путь к базе данных OVAL определений.
                         Если не указан, используется путь по умолчанию.
        """
        self.oval_db_path = oval_db_path or self._find_oval_db()
        self.scanoval_path = self._find_scanoval_binary()
        logger.info(f"ScanOval integration initialized. DB path: {self.oval_db_path}")
    
    def _find_oval_db(self) -> str:
        """Поиск пути к базе данных OVAL."""
        possible_paths = [
            "/var/lib/oval/oval-definitions.xml",
            "/usr/share/oval/oval-definitions.xml",
            "./data/oval-definitions.xml",
            "../data/oval-definitions.xml",
        ]
        
        for path in possible_paths:
            if Path(path).exists():
                logger.debug(f"Found OVAL database at: {path}")
                return path
        
        logger.warning("OVAL database not found, will use online queries")
        return ""
    
    def _find_scanoval_binary(self) -> Optional[str]:
        """Поиск исполняемого файла ScanOval."""
        try:
            result = subprocess.run(
                ["which", "scanoval"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                path = result.stdout.strip()
                logger.debug(f"Found ScanOval binary at: {path}")
                return path
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        # Проверка стандартных путей
        possible_paths = [
            "/usr/local/bin/scanoval",
            "/usr/bin/scanoval",
            "./bin/scanoval",
            "../bin/scanoval",
        ]
        
        for path in possible_paths:
            if Path(path).exists():
                logger.debug(f"Found ScanOval binary at: {path}")
                return path
        
        logger.warning("ScanOval binary not found, will use mock data")
        return None
    
    def query_vulnerabilities(
        self, 
        software_list: List[Dict[str, Any]],
        os_type: str,
        os_version: str
    ) -> List[Vulnerability]:
        """
        Запрос информации об уязвимостях для указанного ПО.
        
        Args:
            software_list: Список установленного ПО.
            os_type: Тип операционной системы.
            os_version: Версия операционной системы.
            
        Returns:
            Список найденных уязвимостей.
        """
        logger.info(f"Querying vulnerabilities for {len(software_list)} software packages on {os_type} {os_version}")
        
        if self.scanoval_path:
            return self._query_with_binary(software_list, os_type, os_version)
        else:
            return self._query_mock(software_list, os_type, os_version)
    
    def _query_with_binary(
        self,
        software_list: List[Dict[str, Any]],
        os_type: str,
        os_version: str
    ) -> List[Vulnerability]:
        """Запрос уязвимостей через бинарный файл ScanOval."""
        vulnerabilities = []
        
        try:
            # Подготовка параметров для ScanOval
            cmd = [
                self.scanoval_path,
                "--os", os_type,
                "--version", os_version,
                "--format", "json",
            ]
            
            if self.oval_db_path:
                cmd.extend(["--database", self.oval_db_path])
            
            # Добавление пакетов для проверки
            for software in software_list:
                cmd.extend([
                    "--package", f"{software['name']}:{software.get('version', 'unknown')}"
                ])
            
            logger.debug(f"Running ScanOval command: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode == 0:
                data = json.loads(result.stdout)
                vulnerabilities = self._parse_scanoval_output(data)
                logger.info(f"Found {len(vulnerabilities)} vulnerabilities via ScanOval")
            else:
                logger.error(f"ScanOval error: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            logger.error("ScanOval query timed out")
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse ScanOval output: {e}")
        except Exception as e:
            logger.error(f"ScanOval query failed: {e}")
        
        return vulnerabilities
    
    def _parse_scanoval_output(self, data: Dict[str, Any]) -> List[Vulnerability]:
        """Парсинг вывода ScanOval в объекты Vulnerability."""
        vulnerabilities = []
        
        for vuln_data in data.get('vulnerabilities', []):
            severity = self._map_severity(vuln_data.get('severity', 'medium'))
            
            vuln = Vulnerability(
                cve_id=vuln_data.get('cve_id'),
                cwe_id=vuln_data.get('cwe_id'),
                capec_id=vuln_data.get('capec_id'),
                title=vuln_data.get('title'),
                description=vuln_data.get('description'),
                severity=severity,
                cvss_score=vuln_data.get('cvss_score'),
                affected_software=vuln_data.get('affected_software', []),
                references=vuln_data.get('references', [])
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _map_severity(self, severity_str: str) -> Severity:
        """Маппинг строки серьёзности в enum Severity."""
        severity_map = {
            'critical': Severity.CRITICAL,
            'high': Severity.HIGH,
            'medium': Severity.MEDIUM,
            'low': Severity.LOW,
            'info': Severity.INFO,
        }
        return severity_map.get(severity_str.lower(), Severity.MEDIUM)
    
    def _query_mock(
        self,
        software_list: List[Dict[str, Any]],
        os_type: str,
        os_version: str
    ) -> List[Vulnerability]:
        """
        Mock-запрос уязвимостей для демонстрации.
        В реальной системе здесь будет вызов ScanOval.
        """
        logger.info("Using mock vulnerability data (ScanOval not available)")
        
        vulnerabilities = []
        
        # Пример уязвимостей для распространённых сервисов
        mock_vulns = {
            'nginx': [
                Vulnerability(
                    cve_id="CVE-2024-1234",
                    cwe_id="CWE-79",
                    title="Nginx XSS Vulnerability",
                    description="Cross-site scripting vulnerability in nginx",
                    severity=Severity.MEDIUM,
                    cvss_score=6.1,
                    affected_software=['nginx'],
                    references=['https://nginx.org/security/advisories']
                ),
            ],
            'apache2': [
                Vulnerability(
                    cve_id="CVE-2024-5678",
                    cwe_id="CWE-22",
                    title="Apache Path Traversal",
                    description="Path traversal vulnerability in Apache HTTP Server",
                    severity=Severity.HIGH,
                    cvss_score=7.5,
                    affected_software=['apache2'],
                    references=['https://httpd.apache.org/security']
                ),
            ],
            'mysql': [
                Vulnerability(
                    cve_id="CVE-2024-9012",
                    cwe_id="CWE-89",
                    title="MySQL SQL Injection",
                    description="SQL injection vulnerability in MySQL",
                    severity=Severity.CRITICAL,
                    cvss_score=9.8,
                    affected_software=['mysql'],
                    references=['https://www.oracle.com/security-alerts']
                ),
            ],
            'openssh': [
                Vulnerability(
                    cve_id="CVE-2024-3456",
                    cwe_id="CWE-787",
                    title="OpenSSH Buffer Overflow",
                    description="Buffer overflow in OpenSSH authentication",
                    severity=Severity.HIGH,
                    cvss_score=7.2,
                    affected_software=['openssh'],
                    references=['https://www.openssh.com/security.html']
                ),
            ],
        }
        
        for software in software_list:
            name = software.get('name', '').lower()
            
            # Проверка на соответствие известным уязвимостям
            for key, vulns in mock_vulns.items():
                if key in name:
                    vulnerabilities.extend(vulns)
                    logger.debug(f"Found mock vulnerabilities for {name}")
        
        logger.info(f"Mock query returned {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities
    
    def update_database(self) -> bool:
        """
        Обновление базы данных OVAL определений.
        
        Returns:
            True если обновление прошло успешно, иначе False.
        """
        logger.info("Updating OVAL database")
        
        if not self.scanoval_path:
            logger.warning("Cannot update database: ScanOval binary not found")
            return False
        
        try:
            result = subprocess.run(
                [self.scanoval_path, "--update"],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                logger.info("OVAL database updated successfully")
                return True
            else:
                logger.error(f"Database update failed: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            logger.error("Database update timed out")
            return False
        except Exception as e:
            logger.error(f"Database update failed: {e}")
            return False
    
    def get_database_info(self) -> Dict[str, Any]:
        """
        Получение информации о базе данных OVAL.
        
        Returns:
            Информация о базе данных (версия, дата обновления, количество определений).
        """
        info = {
            'available': bool(self.scanoval_path),
            'database_path': self.oval_db_path or "N/A",
            'last_updated': None,
            'definition_count': 0,
        }
        
        if self.scanoval_path:
            try:
                result = subprocess.run(
                    [self.scanoval_path, "--info"],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.returncode == 0:
                    # Парсинг информации из вывода
                    for line in result.stdout.split('\n'):
                        if 'Last updated' in line:
                            info['last_updated'] = line.split(':', 1)[1].strip()
                        elif 'Definitions' in line:
                            try:
                                info['definition_count'] = int(line.split(':', 1)[1].strip())
                            except ValueError:
                                pass
            except Exception as e:
                logger.error(f"Failed to get database info: {e}")
        
        return info
