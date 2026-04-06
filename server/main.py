#!/usr/bin/env python3
"""
Main entry point for the server-side security analyzer.

This script performs a complete security analysis:
1. Analyzes server infrastructure
2. Receives scan results from client
3. Correlates with CVE/CWE/CAPEC/MITRE ATT&CK databases
4. Generates comprehensive security reports
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

from shared import (
    ServerInfrastructure,
    ScanResult,
    OpenPort,
    AttackVector,
    logger,
)
from server import ServerAnalyzer, CorrelationEngine, ReportGenerator


def load_scan_results(filepath: str) -> ScanResult:
    """Загрузка результатов сканирования из JSON файла."""
    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # Преобразование данных в объекты
    open_ports = [
        OpenPort(
            port=p['port'],
            protocol=p['protocol'],
            service=p.get('service'),
            version=p.get('version'),
        )
        for p in data.get('open_ports', [])
    ]

    attack_vectors = [
        AttackVector(
            id=v['id'],
            name=v['name'],
            description=v.get('description', ''),
            mitre_technique_id=v.get('mitre_id'),
            mitre_tactic=v.get('mitre_tactic'),
            target_ports=v.get('target_ports', []),
            target_services=v.get('target_services', []),
        )
        for v in data.get('attack_vectors', [])
    ]

    scan_result = ScanResult(
        timestamp=datetime.fromisoformat(data['timestamp']),
        target_ip=data['target_ip'],
        open_ports=open_ports,
        attack_vectors=attack_vectors,
    )

    return scan_result


def run_full_analysis(output_dir: str = "./reports") -> None:
    """Запуск полного анализа безопасности."""
    logger.info("Starting full security analysis")

    # Шаг 1: Анализ инфраструктуры сервера
    logger.info("Step 1: Analyzing server infrastructure")
    analyzer = ServerAnalyzer()
    infrastructure = analyzer.analyze_server()

    print("\n" + "=" * 60)
    print("SERVER INFRASTRUCTURE ANALYSIS")
    print("=" * 60)
    print(f"Hostname: {infrastructure.hostname}")
    print(f"OS: {infrastructure.os_type} {infrastructure.os_version}")
    print(f"Installed Software: {len(infrastructure.installed_software)} packages")
    print(f"Security Measures: {len(infrastructure.security_measures)} detected")
    print(f"Has Database: {infrastructure.has_database}")
    print(f"Has Web Server: {infrastructure.has_web_server}")

    # Шаг 2: Загрузка или создание результатов сканирования
    # В реальном сценарии результаты приходят от клиента
    # Для демонстрации создадим mock данные
    logger.info("Step 2: Loading scan results")
    
    # Создаём тестовые данные для демонстрации
    scan_result = ScanResult(
        timestamp=datetime.now(),
        target_ip="127.0.0.1",
        open_ports=[
            OpenPort(port=22, protocol="tcp", service="ssh"),
            OpenPort(port=80, protocol="tcp", service="http"),
            OpenPort(port=443, protocol="tcp", service="https"),
        ],
        attack_vectors=[],
    )

    # Если есть файл с результатами сканирования, загружаем его
    # scan_result = load_scan_results("scan_results.json")

    print("\n" + "=" * 60)
    print("SCAN RESULTS")
    print("=" * 60)
    print(f"Target: {scan_result.target_ip}")
    print(f"Open Ports: {len(scan_result.open_ports)}")
    for port in scan_result.open_ports:
        print(f"  - Port {port.port}/{port.protocol}: {port.service}")

    # Шаг 3: Корреляция и оценка атак
    logger.info("Step 3: Correlating and assessing attacks")
    engine = CorrelationEngine()
    vulnerabilities = engine.correlate_vulnerabilities(infrastructure, scan_result.attack_vectors)
    report = engine.generate_security_report(infrastructure, vulnerabilities, scan_result.attack_vectors)

    print("\n" + "=" * 60)
    print("ATTACK ASSESSMENT")
    print("=" * 60)
    print(f"Total Vulnerabilities: {report.total_vulnerabilities}")
    print(f"Critical: {report.critical_count}, High: {report.high_count}, Medium: {report.medium_count}, Low: {report.low_count}")
    print(f"\nRealizable Attacks: {report.realizable_attacks}")
    print(f"Non-realizable Attacks: {report.non_realizable_attacks}")

    # Шаг 4: Генерация отчётов
    logger.info("Step 4: Generating reports")
    generator = ReportGenerator()
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    generated_files = generator.generate_all_reports(report, str(output_path))

    print("\n" + "=" * 60)
    print("GENERATED REPORTS")
    print("=" * 60)
    for format_type, filepath in generated_files.items():
        print(f"  {format_type.upper()}: {filepath}")

    print("\n" + "=" * 60)
    print("RECOMMENDATIONS")
    print("=" * 60)
    for i, rec in enumerate(report.recommendations, 1):
        print(f"{i}. {rec.get('title', 'Recommendation')} - Priority: {rec.get('priority', 'N/A')}")

    print("\n" + "=" * 60)
    print("ANALYSIS COMPLETE")
    print("=" * 60)

    return report


def main():
    """Точка входа для серверного анализатора."""
    parser = argparse.ArgumentParser(
        description="Server-side Security Analyzer"
    )
    parser.add_argument(
        "--output-dir", "-o",
        default="./reports",
        help="Directory for output reports"
    )
    parser.add_argument(
        "--scan-results", "-s",
        help="JSON file with scan results from client"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )

    args = parser.parse_args()

    if args.verbose:
        import logging
        logger.setLevel(logging.DEBUG)

    try:
        report = run_full_analysis(args.output_dir)
        print(f"\n✓ Analysis completed successfully!")
        print(f"  Reports saved to: {args.output_dir}/")
        return 0
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        print(f"\n✗ Analysis failed: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
