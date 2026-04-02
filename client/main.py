#!/usr/bin/env python3
"""
Main entry point for the client-side attacker simulator.

This script performs:
1. Port scanning of target server
2. Attack vector identification
3. Sending results to server for analysis
"""

import argparse
import sys
import json
from datetime import datetime
from pathlib import Path

from shared import logger, save_json
from client import perform_scan


def send_to_server(scan_result, server_url: str) -> bool:
    """Отправка результатов сканирования на сервер."""
    try:
        import requests
        
        # Преобразование результатов в JSON
        data = {
            "timestamp": scan_result.timestamp.isoformat(),
            "target_ip": scan_result.target_ip,
            "open_ports": [
                {
                    "port": p.port,
                    "protocol": p.protocol,
                    "service": p.service,
                    "version": p.version,
                }
                for p in scan_result.open_ports
            ],
            "attack_vectors": [
                {
                    "id": v.id,
                    "name": v.name,
                    "description": v.description,
                    "mitre_id": v.mitre_technique_id,
                    "mitre_tactic": v.mitre_tactic,
                    "target_ports": v.target_ports,
                    "target_services": v.target_services,
                }
                for v in scan_result.attack_vectors
            ],
        }

        response = requests.post(
            f"{server_url}/api/scan-results",
            json=data,
            timeout=30
        )

        if response.status_code == 200:
            logger.info("Results sent to server successfully")
            return True
        else:
            logger.error(f"Server returned status {response.status_code}")
            return False

    except ImportError:
        logger.warning("requests library not available, saving to file instead")
        return False
    except Exception as e:
        logger.error(f"Failed to send to server: {e}")
        return False


def main():
    """Точка входа для клиентского сканера."""
    parser = argparse.ArgumentParser(
        description="Client-side Attacker Simulator - Port Scanner and Attack Vector Identifier"
    )
    parser.add_argument(
        "--target", "-t",
        required=True,
        help="Target IP address or hostname"
    )
    parser.add_argument(
        "--output", "-o",
        help="Output file for scan results (JSON)"
    )
    parser.add_argument(
        "--server", "-s",
        help="Server URL to send results (e.g., http://localhost:8000)"
    )
    parser.add_argument(
        "--ports", "-p",
        help="Comma-separated list of ports to scan (default: common ports)"
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
        print("\n" + "=" * 60)
        print("ATTACKER SIMULATOR - PORT SCANNER")
        print("=" * 60)
        print(f"Target: {args.target}")
        print(f"Started: {datetime.now().isoformat()}")
        print("-" * 60)

        # Выполнение сканирования
        result = perform_scan(args.target)

        # Вывод результатов
        print("\n" + "=" * 60)
        print("SCAN RESULTS")
        print("=" * 60)

        print(f"\nOpen Ports: {len(result.open_ports)}")
        if result.open_ports:
            for port in result.open_ports:
                print(f"  • Port {port.port}/{port.protocol}: {port.service}")
                if port.version:
                    print(f"      Version: {port.version[:50]}...")
        else:
            print("  No open ports found")

        print(f"\nIdentified Attack Vectors: {len(result.attack_vectors)}")
        if result.attack_vectors:
            for vector in result.attack_vectors:
                print(f"  ⚠️  {vector.name} ({vector.id})")
                print(f"      MITRE: {vector.mitre_technique_id} - {vector.mitre_tactic}")
        else:
            print("  No attack vectors identified")

        # Сохранение результатов
        output_file = args.output
        if not output_file:
            output_file = f"scan_results_{args.target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d%H%M%S')}.json"

        save_json({
            "timestamp": result.timestamp.isoformat(),
            "target_ip": result.target_ip,
            "open_ports": [
                {"port": p.port, "protocol": p.protocol, "service": p.service, "version": p.version}
                for p in result.open_ports
            ],
            "attack_vectors": [
                {
                    "id": v.id,
                    "name": v.name,
                    "description": v.description,
                    "mitre_id": v.mitre_technique_id,
                    "mitre_tactic": v.mitre_tactic,
                    "target_ports": v.target_ports,
                    "target_services": v.target_services,
                }
                for v in result.attack_vectors
            ],
        }, output_file)

        print(f"\n✓ Results saved to: {output_file}")

        # Отправка на сервер
        if args.server:
            print(f"\nSending results to server: {args.server}")
            if send_to_server(result, args.server):
                print("✓ Results sent to server successfully")
            else:
                print("✗ Failed to send results to server")
                print("  Results are saved locally")

        print("\n" + "=" * 60)
        print("SCAN COMPLETE")
        print("=" * 60)

        return 0

    except KeyboardInterrupt:
        print("\n\n✗ Scan interrupted by user")
        return 130
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        print(f"\n✗ Scan failed: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
