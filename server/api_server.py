#!/usr/bin/env python3
"""
Server API for receiving scan results from attacker client and processing vulnerability database.
This module provides a REST API for:
1. Receiving scan results (Nmap + NSE scripts) from attacker client
2. Processing vulnerability database via ScanOval
3. Correlating vulnerabilities with server infrastructure
4. Generating security reports
"""

import logging
import sys
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any

from flask import Flask, request, jsonify
from flask_cors import CORS

from shared import (
    ServerInfrastructure,
    ScanResult,
    OpenPort,
    AttackVector,
    Vulnerability,
    logger,
    setup_logging,
)
from server import ServerAnalyzer, CorrelationEngine, ReportGenerator
from server.scanner import ScanOvalIntegration

# Setup logging
setup_logging(level=logging.DEBUG)
logger = logging.getLogger("server_api")

app = Flask(__name__)
CORS(app)  # Enable CORS for cross-origin requests from client

# Global state
current_scan_result: Optional[ScanResult] = None
current_infrastructure: Optional[ServerInfrastructure] = None
last_report: Optional[Dict[str, Any]] = None


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'service': 'security-analyzer-server'
    })


@app.route('/api/scan-results', methods=['POST'])
def receive_scan_results():
    """
    Receive scan results from attacker client.
    Expected JSON format:
    {
        "timestamp": "2024-01-01T12:00:00",
        "target_ip": "192.168.1.1",
        "open_ports": [
            {"port": 22, "protocol": "tcp", "service": "ssh", "version": "OpenSSH 8.2"}
        ],
        "attack_vectors": [
            {"id": "AV001", "name": "SSH Brute Force", ...}
        ]
    }
    """
    global current_scan_result
    
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        
        logger.info(f"Received scan results from {data.get('target_ip', 'unknown')}")
        logger.debug(f"Scan data: {data}")
        
        # Parse open ports
        open_ports = []
        for port_data in data.get('open_ports', []):
            open_ports.append({
                'port': port_data.get('port'),
                'protocol': port_data.get('protocol', 'tcp'),
                'service': port_data.get('service'),
                'version': port_data.get('version'),
                'state': 'open'
            })
        
        # Parse attack vectors
        attack_vectors = []
        for vector_data in data.get('attack_vectors', []):
            attack_vectors.append(AttackVector(
                id=vector_data.get('id', 'UNKNOWN'),
                name=vector_data.get('name', 'Unknown Attack'),
                description=vector_data.get('description', ''),
                mitre_technique_id=vector_data.get('mitre_id'),
                mitre_tactic=vector_data.get('mitre_tactic'),
                target_ports=vector_data.get('target_ports', []),
                target_services=vector_data.get('target_services', []),
                is_realizable=True
            ))
        
        # Create ScanResult object
        timestamp_str = data.get('timestamp', datetime.now().isoformat())
        try:
            timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        except ValueError:
            timestamp = datetime.now()
        
        current_scan_result = ScanResult(
            timestamp=timestamp,
            target_ip=data.get('target_ip', 'unknown'),
            open_ports=open_ports,
            identified_services=[],
            potential_vulnerabilities=[],
            attack_vectors=attack_vectors
        )
        
        logger.info(f"Stored scan result: {len(open_ports)} ports, {len(attack_vectors)} attack vectors")
        
        # Trigger vulnerability analysis with ScanOval
        analysis_result = process_vulnerabilities()
        
        return jsonify({
            'status': 'success',
            'message': 'Scan results received and processed',
            'scan_id': timestamp.isoformat(),
            'ports_received': len(open_ports),
            'vectors_received': len(attack_vectors),
            'analysis': analysis_result
        }), 200
        
    except Exception as e:
        logger.error(f"Error processing scan results: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/api/vulnerability-db', methods=['POST'])
def receive_vulnerability_database():
    """
    Receive vulnerability database from attacker client.
    The client can send pre-collected vulnerability data for processing.
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        
        logger.info("Received vulnerability database from client")
        
        # Process the vulnerability database
        vuln_count = len(data.get('vulnerabilities', []))
        logger.info(f"Processing {vuln_count} vulnerabilities from client database")
        
        # Store for correlation
        if current_scan_result:
            for vuln_data in data.get('vulnerabilities', []):
                vuln = Vulnerability(
                    cve_id=vuln_data.get('cve_id'),
                    cwe_id=vuln_data.get('cwe_id'),
                    capec_id=vuln_data.get('capec_id'),
                    title=vuln_data.get('title'),
                    description=vuln_data.get('description'),
                    severity=vuln_data.get('severity', 'medium'),
                    cvss_score=vuln_data.get('cvss_score'),
                    affected_software=vuln_data.get('affected_software', []),
                    references=vuln_data.get('references', [])
                )
                current_scan_result.potential_vulnerabilities.append(vuln)
        
        return jsonify({
            'status': 'success',
            'message': f'Processed {vuln_count} vulnerabilities',
            'vulnerabilities_stored': vuln_count
        }), 200
        
    except Exception as e:
        logger.error(f"Error processing vulnerability database: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/api/analyze', methods=['POST'])
def trigger_analysis():
    """
    Trigger full security analysis using received scan results.
    """
    global current_infrastructure, last_report
    
    try:
        logger.info("Starting full security analysis")
        
        if not current_scan_result:
            return jsonify({'error': 'No scan results available. Send scan results first.'}), 400
        
        # Analyze server infrastructure
        analyzer = ServerAnalyzer()
        current_infrastructure = analyzer.analyze_server()
        logger.info(f"Server infrastructure analyzed: {current_infrastructure.hostname}")
        
        # Query ScanOval for vulnerabilities
        oval_integration = ScanOvalIntegration()
        additional_vulns = oval_integration.query_vulnerabilities(
            software_list=current_infrastructure.installed_software,
            os_type=current_infrastructure.os_type,
            os_version=current_infrastructure.os_version
        )
        
        # Add ScanOval vulnerabilities to scan result
        current_scan_result.potential_vulnerabilities.extend(additional_vulns)
        logger.info(f"Added {len(additional_vulns)} vulnerabilities from ScanOval")
        
        # Correlate vulnerabilities
        engine = CorrelationEngine()
        vulnerabilities = engine.correlate_vulnerabilities(
            current_infrastructure, 
            current_scan_result.attack_vectors
        )
        
        # Generate security report
        report = engine.generate_security_report(
            current_infrastructure,
            vulnerabilities,
            current_scan_result.attack_vectors
        )
        
        # Generate report files
        generator = ReportGenerator()
        output_path = Path("./reports")
        output_path.mkdir(parents=True, exist_ok=True)
        generated_files = generator.generate_all_reports(report, str(output_path))
        
        last_report = {
            'total_vulnerabilities': report.total_vulnerabilities,
            'critical_count': report.critical_count,
            'high_count': report.high_count,
            'medium_count': report.medium_count,
            'low_count': report.low_count,
            'realizable_attacks': report.realizable_attacks,
            'generated_files': generated_files
        }
        
        logger.info(f"Analysis complete: {report.total_vulnerabilities} vulnerabilities found")
        
        return jsonify({
            'status': 'success',
            'message': 'Security analysis completed',
            'report': last_report
        }), 200
        
    except Exception as e:
        logger.error(f"Analysis failed: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/api/report', methods=['GET'])
def get_report():
    """Get the latest analysis report."""
    if not last_report:
        return jsonify({'error': 'No report available. Run analysis first.'}), 404
    
    return jsonify({
        'status': 'success',
        'report': last_report
    }), 200


@app.route('/api/status', methods=['GET'])
def get_status():
    """Get current server status."""
    return jsonify({
        'status': 'running',
        'has_scan_results': current_scan_result is not None,
        'has_infrastructure_data': current_infrastructure is not None,
        'has_report': last_report is not None,
        'scan_result_summary': {
            'target_ip': current_scan_result.target_ip if current_scan_result else None,
            'open_ports': len(current_scan_result.open_ports) if current_scan_result else 0,
            'attack_vectors': len(current_scan_result.attack_vectors) if current_scan_result else 0,
        } if current_scan_result else None
    }), 200


def process_vulnerabilities() -> Dict[str, Any]:
    """Process vulnerabilities using ScanOval."""
    try:
        if not current_scan_result or not current_infrastructure:
            return {'status': 'pending', 'message': 'Waiting for infrastructure data'}
        
        oval = ScanOvalIntegration()
        vulns = oval.query_vulnerabilities(
            software_list=current_infrastructure.installed_software,
            os_type=current_infrastructure.os_type,
            os_version=current_infrastructure.os_version
        )
        
        return {
            'status': 'complete',
            'vulnerabilities_found': len(vulns),
            'scanoval_available': oval.scanoval_path is not None
        }
        
    except Exception as e:
        logger.error(f"Vulnerability processing error: {e}")
        return {'status': 'error', 'message': str(e)}


def run_server(host: str = '0.0.0.0', port: int = 8000, debug: bool = False):
    """Run the Flask server."""
    logger.info(f"Starting server API on {host}:{port}")
    app.run(host=host, port=port, debug=debug, threaded=True)


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description="Security Analyzer Server API")
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=8000, help='Port to bind to')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    
    args = parser.parse_args()
    
    try:
        run_server(host=args.host, port=args.port, debug=args.debug)
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Server failed: {e}")
        sys.exit(1)
