"""
Report generator for security analysis results.
"""

import json
from typing import Any
from datetime import datetime


class ReportGenerator:
    """Генератор отчётов о безопасности."""

    def generate_all_reports(self, report: Any, output_dir: str) -> dict:
        """Генерация всех форматов отчётов."""
        import os
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        generated_files = {}
        
        # JSON report
        json_file = os.path.join(output_dir, f"security_report_{timestamp}.json")
        self.generate_json_report(report, json_file)
        generated_files['json'] = json_file
        
        # HTML report
        html_file = os.path.join(output_dir, f"security_report_{timestamp}.html")
        self.generate_html_report(report, html_file)
        generated_files['html'] = html_file
        
        # Text report
        txt_file = os.path.join(output_dir, f"security_report_{timestamp}.txt")
        self.generate_text_report(report, txt_file)
        generated_files['text'] = txt_file
        
        return generated_files

    def generate_json_report(self, report: Any, filename: str):
        """Генерация JSON отчёта."""
        data = {
            'report_id': report.report_id,
            'generated_at': report.generated_at.isoformat(),
            'summary': {
                'total_vulnerabilities': report.total_vulnerabilities,
                'critical_count': report.critical_count,
                'high_count': report.high_count,
                'medium_count': report.medium_count,
                'low_count': report.low_count,
                'realizable_attacks': report.realizable_attacks,
                'non_realizable_attacks': report.non_realizable_attacks
            },
            'recommendations': report.recommendations
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def generate_html_report(self, report: Any, filename: str):
        """Генерация HTML отчёта."""
        html = f"""<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Security Report - {report.report_id}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #2196F3; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }}
        .stat-card {{ background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; }}
        .stat-value {{ font-size: 2em; font-weight: bold; color: #2196F3; }}
        .stat-label {{ color: #666; margin-top: 5px; }}
        .critical {{ color: #f44336; }}
        .high {{ color: #ff9800; }}
        .medium {{ color: #ffc107; }}
        .low {{ color: #4caf50; }}
        .recommendation {{ background: #e3f2fd; padding: 15px; margin: 10px 0; border-radius: 5px; border-left: 4px solid #2196F3; }}
        .priority-Critical {{ border-left-color: #f44336; }}
        .priority-High {{ border-left-color: #ff9800; }}
        .priority-Medium {{ border-left-color: #ffc107; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Security Analysis Report</h1>
        <p><strong>Report ID:</strong> {report.report_id}</p>
        <p><strong>Generated:</strong> {report.generated_at.strftime('%Y-%m-%d %H:%M:%S')}</p>
        
        <h2>Summary</h2>
        <div class="summary">
            <div class="stat-card">
                <div class="stat-value">{report.total_vulnerabilities}</div>
                <div class="stat-label">Total Vulnerabilities</div>
            </div>
            <div class="stat-card">
                <div class="stat-value critical">{report.critical_count}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card">
                <div class="stat-value high">{report.high_count}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-card">
                <div class="stat-value medium">{report.medium_count}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-card">
                <div class="stat-value low">{report.low_count}</div>
                <div class="stat-label">Low</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: #4caf50;">{report.realizable_attacks}</div>
                <div class="stat-label">Realizable Attacks</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: #9e9e9e;">{report.non_realizable_attacks}</div>
                <div class="stat-label">Non-Realizable Attacks</div>
            </div>
        </div>
        
        <h2>Recommendations</h2>
"""
        for rec in report.recommendations:
            priority_class = f"priority-{rec.get('priority', 'Medium')}"
            html += f"""
        <div class="recommendation {priority_class}">
            <h3>{rec['title']}</h3>
            <p><strong>Priority:</strong> {rec['priority']}</p>
            <p>{rec['description']}</p>
            <pre>{rec['implementation_steps']}</pre>
        </div>
"""
        
        html += """
    </div>
</body>
</html>"""
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)

    def generate_text_report(self, report: Any, filename: str):
        """Генерация текстового отчёта."""
        text = f"""
================================================================================
SECURITY ANALYSIS REPORT
================================================================================

Report ID: {report.report_id}
Generated: {report.generated_at.strftime('%Y-%m-%d %H:%M:%S')}

--------------------------------------------------------------------------------
SUMMARY
--------------------------------------------------------------------------------

Total Vulnerabilities:     {report.total_vulnerabilities}
Critical:                  {report.critical_count}
High:                      {report.high_count}
Medium:                    {report.medium_count}
Low:                       {report.low_count}

Realizable Attacks:        {report.realizable_attacks}
Non-Realizable Attacks:    {report.non_realizable_attacks}

--------------------------------------------------------------------------------
RECOMMENDATIONS
--------------------------------------------------------------------------------

"""
        for i, rec in enumerate(report.recommendations, 1):
            text += f"""
{i}. {rec['title']}
   Priority: {rec['priority']}
   Description: {rec['description']}
   Implementation:
{rec['implementation_steps']}

"""
        
        text += """
================================================================================
END OF REPORT
================================================================================
"""
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(text)
