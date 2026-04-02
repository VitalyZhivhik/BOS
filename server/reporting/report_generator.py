"""
Reporting module for generating security reports in various formats.
"""

import json
from typing import Dict, Any, Optional
from datetime import datetime
from pathlib import Path

from jinja2 import Template

from shared import (
    SecurityReport,
    AttackAssessment,
    AttackFeasibility,
    logger,
)


class ReportGenerator:
    """Генератор отчётов о безопасности."""

    def __init__(self):
        self.html_template = self._get_html_template()
        self.text_template = self._get_text_template()

    def _get_html_template(self) -> str:
        """HTML шаблон для отчёта."""
        return """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Report - {{ report.report_id }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .section { margin: 20px 0; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }
        .feasible { background: #ffebee; border-left: 4px solid #f44336; }
        .infeasible { background: #e8f5e9; border-left: 4px solid #4caf50; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }
        th { background: #f5f5f5; }
        .priority-1 { color: #d32f2f; font-weight: bold; }
        .priority-2 { color: #f57c00; font-weight: bold; }
        .priority-3 { color: #fbc02d; }
        .summary { background: #fff3e0; padding: 15px; border-radius: 5px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Assessment Report</h1>
        <p>Report ID: {{ report.report_id }}</p>
        <p>Generated: {{ report.generated_at }}</p>
        <p>Target: {{ report.server_infrastructure.hostname }}</p>
    </div>

    <div class="summary">
        <h2>Summary</h2>
        <p>{{ report.summary }}</p>
        <p><strong>Feasible Attacks:</strong> {{ report.feasible_attacks|length }}</p>
        <p><strong>Infeasible Attacks:</strong> {{ report.infeasible_attacks|length }}</p>
    </div>

    <div class="section">
        <h2>Server Infrastructure</h2>
        <table>
            <tr><th>Property</th><th>Value</th></tr>
            <tr><td>Hostname</td><td>{{ report.server_infrastructure.hostname }}</td></tr>
            <tr><td>OS</td><td>{{ report.server_infrastructure.os_type }} {{ report.server_infrastructure.os_version }}</td></tr>
            <tr><td>Installed Software</td><td>{{ report.server_infrastructure.installed_software }} packages</td></tr>
            <tr><td>Security Tools</td><td>{{ report.server_infrastructure.security_tools }} detected</td></tr>
            <tr><td>Has Database</td><td>{{ "Yes" if report.server_infrastructure.has_database else "No" }}</td></tr>
            <tr><td>Has Web Server</td><td>{{ "Yes" if report.server_infrastructure.has_web_server else "No" }}</td></tr>
            <tr><td>Open Ports</td><td>{{ report.scan_results.open_ports }}</td></tr>
        </table>
    </div>

    {% if report.feasible_attacks %}
    <div class="section feasible">
        <h2>⚠️ Feasible Attacks (Require Immediate Attention)</h2>
        <table>
            <tr>
                <th>Priority</th>
                <th>Attack Name</th>
                <th>MITRE Technique</th>
                <th>Affected Components</th>
            </tr>
            {% for attack in report.feasible_attacks %}
            <tr>
                <td class="priority-{{ attack.priority }}">{{ attack.priority }}</td>
                <td>{{ attack.attack_vector.name }}</td>
                <td>{{ attack.attack_vector.mitre_technique_id or 'N/A' }}</td>
                <td>{{ attack.affected_components|join(', ') or 'Multiple' }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>
    {% endif %}

    {% if report.infeasible_attacks %}
    <div class="section infeasible">
        <h2>✓ Infeasible Attacks (Not Applicable)</h2>
        <table>
            <tr>
                <th>Attack Name</th>
                <th>Reason</th>
            </tr>
            {% for attack in report.infeasible_attacks %}
            <tr>
                <td>{{ attack.attack_vector.name }}</td>
                <td>{{ attack.reason }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>
    {% endif %}

    {% if report.remediation_recommendations %}
    <div class="section">
        <h2>🔧 Remediation Recommendations</h2>
        <ol>
            {% for rec in report.remediation_recommendations %}
            <li>{{ rec }}</li>
            {% endfor %}
        </ol>
    </div>
    {% endif %}

    <div class="section">
        <h2>Detailed Attack Assessments</h2>
        {% for assessment in report.attack_assessments %}
        <div style="margin: 15px 0; padding: 15px; border: 1px solid #ddd;">
            <h3>{{ assessment.attack_vector.name }}</h3>
            <p><strong>ID:</strong> {{ assessment.attack_vector.id }}</p>
            <p><strong>Feasibility:</strong> 
                <span style="color: {{ '#f44336' if assessment.feasibility.value == 'feasible' else '#4caf50' }}">
                    {{ assessment.feasibility.value.upper() }}
                </span>
            </p>
            <p><strong>Description:</strong> {{ assessment.attack_vector.description }}</p>
            <p><strong>Reason:</strong> {{ assessment.reason }}</p>
            {% if assessment.remediation_steps %}
            <p><strong>Remediation Steps:</strong></p>
            <ul>
                {% for step in assessment.remediation_steps %}
                <li>{{ step }}</li>
                {% endfor %}
            </ul>
            {% endif %}
        </div>
        {% endfor %}
    </div>

    <footer style="margin-top: 40px; text-align: center; color: #666;">
        <p>Generated by Security Analysis System</p>
    </footer>
</body>
</html>
        """.strip()

    def _get_text_template(self) -> str:
        """Текстовый шаблон для отчёта."""
        return """
================================================================================
                        SECURITY ASSESSMENT REPORT
================================================================================

Report ID: {{ report.report_id }}
Generated: {{ report.generated_at }}
Target: {{ report.server_infrastructure.hostname }}

--------------------------------------------------------------------------------
                                   SUMMARY
--------------------------------------------------------------------------------
{{ report.summary }}

Feasible Attacks: {{ report.feasible_attacks|length }}
Infeasible Attacks: {{ report.infeasible_attacks|length }}

--------------------------------------------------------------------------------
                            SERVER INFRASTRUCTURE
--------------------------------------------------------------------------------
Hostname: {{ report.server_infrastructure.hostname }}
OS: {{ report.server_infrastructure.os_type }} {{ report.server_infrastructure.os_version }}
Installed Software: {{ report.server_infrastructure.installed_software }} packages
Security Tools: {{ report.server_infrastructure.security_tools }} detected
Has Database: {{ "Yes" if report.server_infrastructure.has_database else "No" }}
Has Web Server: {{ "Yes" if report.server_infrastructure.has_web_server else "No" }}
Open Ports: {{ report.scan_results.open_ports }}

{% if report.feasible_attacks %}
--------------------------------------------------------------------------------
                    ⚠️  FEASIBLE ATTACKS (ACTION REQUIRED)
--------------------------------------------------------------------------------
{% for attack in report.feasible_attacks %}
[Priority {{ attack.priority }}] {{ attack.attack_vector.name }}
  MITRE Technique: {{ attack.attack_vector.mitre_technique_id or 'N/A' }}
  Affected: {{ attack.affected_components|join(', ') or 'Multiple' }}
  Reason: {{ attack.reason }}
{% endfor %}
{% endif %}

{% if report.infeasible_attacks %}
--------------------------------------------------------------------------------
                      ✓ INFEASIBLE ATTACKS (NOT APPLICABLE)
--------------------------------------------------------------------------------
{% for attack in report.infeasible_attacks %}
• {{ attack.attack_vector.name }}
  Reason: {{ attack.reason }}
{% endfor %}
{% endif %}

{% if report.remediation_recommendations %}
--------------------------------------------------------------------------------
                       🔧 REMEDIATION RECOMMENDATIONS
--------------------------------------------------------------------------------
{% for rec in report.remediation_recommendations %}
{{ loop.index }}. {{ rec }}
{% endfor %}
{% endif %}

================================================================================
                           END OF REPORT
================================================================================
        """.strip()

    def generate_html_report(self, report: SecurityReport, output_path: str) -> str:
        """Генерация HTML отчёта."""
        template = Template(self.html_template)
        
        # Преобразование данных для шаблона
        report_dict = self._report_to_dict(report)
        
        html_content = template.render(**report_dict)
        
        Path(output_path).write_text(html_content, encoding='utf-8')
        logger.info(f"HTML report generated: {output_path}")
        
        return output_path

    def generate_text_report(self, report: SecurityReport, output_path: str) -> str:
        """Генерация текстового отчёта."""
        template = Template(self.text_template)
        
        report_dict = self._report_to_dict(report)
        
        text_content = template.render(**report_dict)
        
        Path(output_path).write_text(text_content, encoding='utf-8')
        logger.info(f"Text report generated: {output_path}")
        
        return output_path

    def generate_json_report(self, report: SecurityReport, output_path: str) -> str:
        """Генерация JSON отчёта."""
        report_dict = self._report_to_dict(report)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report_dict, f, indent=2, ensure_ascii=False, default=str)
        
        logger.info(f"JSON report generated: {output_path}")
        
        return output_path

    def _report_to_dict(self, report: SecurityReport) -> Dict[str, Any]:
        """Преобразование отчёта в словарь для шаблонов."""
        return {
            "report": {
                "report_id": report.report_id,
                "generated_at": report.generated_at.isoformat(),
                "summary": report.summary,
                "server_infrastructure": {
                    "hostname": report.server_infrastructure.hostname,
                    "os_type": report.server_infrastructure.os_type,
                    "os_version": report.server_infrastructure.os_version,
                    "installed_software": len(report.server_infrastructure.installed_software),
                    "security_tools": len(report.server_infrastructure.security_tools),
                    "has_database": report.server_infrastructure.has_database,
                    "has_web_server": report.server_infrastructure.has_web_server,
                },
                "scan_results": {
                    "open_ports": len(report.scan_results.open_ports) if report.scan_results.open_ports else 0,
                },
                "feasible_attacks": [
                    self._assessment_to_dict(a) for a in report.feasible_attacks
                ],
                "infeasible_attacks": [
                    self._assessment_to_dict(a) for a in report.infeasible_attacks
                ],
                "attack_assessments": [
                    self._assessment_to_dict(a) for a in report.attack_assessments
                ],
                "remediation_recommendations": report.remediation_recommendations,
            }
        }

    def _assessment_to_dict(self, assessment: AttackAssessment) -> Dict[str, Any]:
        """Преобразование оценки атаки в словарь."""
        return {
            "attack_vector": {
                "id": assessment.attack_vector.id,
                "name": assessment.attack_vector.name,
                "description": assessment.attack_vector.description,
                "mitre_technique_id": assessment.attack_vector.mitre_technique_id,
                "mitre_tactic": assessment.attack_vector.mitre_tactic,
            },
            "feasibility": assessment.feasibility.value,
            "reason": assessment.reason,
            "affected_components": assessment.affected_components,
            "remediation_steps": assessment.remediation_steps,
            "priority": assessment.priority,
        }

    def generate_all_reports(
        self,
        report: SecurityReport,
        output_dir: str,
        base_filename: Optional[str] = None,
    ) -> Dict[str, str]:
        """Генерация всех форматов отчётов."""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        filename_base = base_filename or report.report_id

        generated_files = {}

        # HTML
        html_path = output_path / f"{filename_base}.html"
        generated_files["html"] = self.generate_html_report(report, str(html_path))

        # Text
        text_path = output_path / f"{filename_base}.txt"
        generated_files["text"] = self.generate_text_report(report, str(text_path))

        # JSON
        json_path = output_path / f"{filename_base}.json"
        generated_files["json"] = self.generate_json_report(report, str(json_path))

        logger.info(f"All reports generated in {output_dir}")

        return generated_files


def main():
    """Демонстрация генератора отчётов."""
    print("Report Generator initialized")
    print("Use generate_all_reports() to create reports from SecurityReport objects")


if __name__ == "__main__":
    main()
