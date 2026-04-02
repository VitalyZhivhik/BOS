#!/usr/bin/env python3
"""
Server GUI Application for BOS (Security Analysis System)
Analyzes server security, correlates with CVE/CWE/CAPEC/MITRE databases
"""

import customtkinter as ctk
from tkinter import messagebox, filedialog
import threading
import json
import os
import sys
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.models import ServerInfo, Vulnerability, AttackVector, SecurityReport
from server.analyzer.server_analyzer import ServerAnalyzer
from server.correlation.engine import CorrelationEngine
from server.reporting.report_generator import ReportGenerator


class ServerGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        # Configure window
        self.title("BOS Server - Security Analysis System")
        self.geometry("1200x800")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        # Initialize components
        self.analyzer = ServerAnalyzer()
        self.correlator = CorrelationEngine()
        self.report_gen = ReportGenerator()
        
        self.current_report = None
        self.analysis_complete = False
        
        # Create UI
        self._create_ui()
        
    def _create_ui(self):
        """Create the main user interface"""
        # Main container
        self.main_frame = ctk.CTkFrame(self)
        self.main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Header
        self.header_frame = ctk.CTkFrame(self.main_frame)
        self.header_frame.pack(fill="x", pady=(0, 20))
        
        self.title_label = ctk.CTkLabel(
            self.header_frame, 
            text="🛡️ BOS Server Security Analyzer",
            font=ctk.CTkFont(size=24, weight="bold")
        )
        self.title_label.pack(pady=10)
        
        self.status_label = ctk.CTkLabel(
            self.header_frame,
            text="Status: Ready",
            font=ctk.CTkFont(size=14),
            text_color="gray"
        )
        self.status_label.pack()
        
        # Control panel
        self.control_frame = ctk.CTkFrame(self.main_frame)
        self.control_frame.pack(fill="x", pady=10)
        
        self.start_btn = ctk.CTkButton(
            self.control_frame,
            text="🚀 Start Analysis",
            command=self._start_analysis,
            height=40,
            font=ctk.CTkFont(size=16)
        )
        self.start_btn.pack(side="left", padx=10)
        
        self.export_btn = ctk.CTkButton(
            self.control_frame,
            text="📊 Export Report",
            command=self._export_report,
            state="disabled",
            height=40,
            font=ctk.CTkFont(size=16)
        )
        self.export_btn.pack(side="left", padx=10)
        
        self.clear_btn = ctk.CTkButton(
            self.control_frame,
            text="🗑️ Clear Results",
            command=self._clear_results,
            height=40,
            font=ctk.CTkFont(size=16)
        )
        self.clear_btn.pack(side="left", padx=10)
        
        # Progress bar
        self.progress_frame = ctk.CTkFrame(self.main_frame)
        self.progress_frame.pack(fill="x", pady=10)
        
        self.progress_bar = ctk.CTkProgressBar(self.progress_frame)
        self.progress_bar.pack(fill="x", padx=20, pady=10)
        self.progress_bar.set(0)
        
        self.progress_label = ctk.CTkLabel(
            self.progress_frame,
            text="Progress: 0%",
            font=ctk.CTkFont(size=12)
        )
        self.progress_label.pack()
        
        # Results notebook (tabs)
        self.notebook = ctk.CTkTabview(self.main_frame)
        self.notebook.pack(fill="both", expand=True, pady=10)
        
        # Tab 1: Server Info
        self.server_info_tab = self.notebook.add("Server Info")
        self._create_server_info_tab()
        
        # Tab 2: Vulnerabilities
        self.vuln_tab = self.notebook.add("Vulnerabilities")
        self._create_vulnerabilities_tab()
        
        # Tab 3: Attack Vectors
        self.attack_tab = self.notebook.add("Attack Vectors")
        self._create_attack_vectors_tab()
        
        # Tab 4: Recommendations
        self.recommendations_tab = self.notebook.add("Recommendations")
        self._create_recommendations_tab()
        
        # Log panel
        self.log_frame = ctk.CTkFrame(self.main_frame, height=150)
        self.log_frame.pack(fill="x", pady=10)
        
        self.log_label = ctk.CTkLabel(
            self.log_frame,
            text="Activity Log:",
            font=ctk.CTkFont(weight="bold")
        )
        self.log_label.pack(anchor="w", padx=10, pady=5)
        
        self.log_text = ctk.CTkTextbox(self.log_frame, height=100)
        self.log_text.pack(fill="both", expand=True, padx=10, pady=5)
        
    def _create_server_info_tab(self):
        """Create server information tab"""
        self.server_info_text = ctk.CTkTextbox(self.server_info_tab)
        self.server_info_text.pack(fill="both", expand=True, padx=10, pady=10)
        
    def _create_vulnerabilities_tab(self):
        """Create vulnerabilities tab"""
        # Frame for filters
        self.vuln_filter_frame = ctk.CTkFrame(self.vuln_tab)
        self.vuln_filter_frame.pack(fill="x", padx=10, pady=5)
        
        ctk.CTkLabel(self.vuln_filter_frame, text="Filter by severity:").pack(side="left", padx=5)
        
        self.severity_var = ctk.StringVar(value="All")
        self.severity_menu = ctk.CTkOptionMenu(
            self.vuln_filter_frame,
            variable=self.severity_var,
            values=["All", "Critical", "High", "Medium", "Low"],
            command=self._filter_vulnerabilities
        )
        self.severity_menu.pack(side="left", padx=5)
        
        # Vulnerabilities list
        self.vuln_text = ctk.CTkTextbox(self.vuln_tab)
        self.vuln_text.pack(fill="both", expand=True, padx=10, pady=10)
        
    def _create_attack_vectors_tab(self):
        """Create attack vectors tab"""
        # Filter frame
        self.attack_filter_frame = ctk.CTkFrame(self.attack_tab)
        self.attack_filter_frame.pack(fill="x", padx=10, pady=5)
        
        ctk.CTkLabel(self.attack_filter_frame, text="Show:").pack(side="left", padx=5)
        
        self.attack_filter_var = ctk.StringVar(value="All")
        self.attack_filter_menu = ctk.CTkOptionMenu(
            self.attack_filter_frame,
            variable=self.attack_filter_var,
            values=["All", "Realizable", "Not Realizable"],
            command=self._filter_attacks
        )
        self.attack_filter_menu.pack(side="left", padx=5)
        
        # Attack vectors list
        self.attack_text = ctk.CTkTextbox(self.attack_tab)
        self.attack_text.pack(fill="both", expand=True, padx=10, pady=10)
        
    def _create_recommendations_tab(self):
        """Create recommendations tab"""
        self.recommendations_text = ctk.CTkTextbox(self.recommendations_tab)
        self.recommendations_text.pack(fill="both", expand=True, padx=10, pady=10)
        
    def _log_message(self, message):
        """Add message to log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert("end", f"[{timestamp}] {message}\n")
        self.log_text.see("end")
        
    def _update_progress(self, value, label=""):
        """Update progress bar"""
        self.progress_bar.set(value / 100)
        self.progress_label.configure(text=f"Progress: {value}% {label}")
        self.update_idletasks()
        
    def _start_analysis(self):
        """Start security analysis in background thread"""
        if not self.analysis_complete:
            self.start_btn.configure(state="disabled")
            self._log_message("Starting security analysis...")
            self._update_progress(0, "Initializing...")
            
            # Run analysis in background thread
            thread = threading.Thread(target=self._run_analysis, daemon=True)
            thread.start()
        else:
            messagebox.showinfo("Info", "Analysis already completed. Clear results to start new analysis.")
            
    def _run_analysis(self):
        """Run the complete security analysis"""
        try:
            # Step 1: Analyze server
            self._log_message("Analyzing server configuration...")
            self._update_progress(10, "Analyzing server...")
            server_info = self.analyzer.analyze_server()
            
            # Update server info tab
            self._display_server_info(server_info)
            self._log_message(f"Found {len(server_info.installed_software)} software packages")
            
            # Step 2: Get attack vectors from client (simulated for now)
            self._log_message("Loading attack vectors...")
            self._update_progress(40, "Loading attack vectors...")
            attack_vectors = self._load_attack_vectors()
            
            # Step 3: Correlate with databases
            self._log_message("Correlating with CVE/CWE/CAPEC/MITRE databases...")
            self._update_progress(60, "Correlating data...")
            vulnerabilities = self.correlator.correlate_vulnerabilities(
                server_info, attack_vectors
            )
            
            # Step 4: Generate report
            self._log_message("Generating security report...")
            self._update_progress(80, "Generating report...")
            report = self.correlator.generate_security_report(
                server_info, vulnerabilities, attack_vectors
            )
            
            self.current_report = report
            
            # Display results
            self._display_vulnerabilities(vulnerabilities)
            self._display_attack_vectors(attack_vectors)
            self._display_recommendations(report)
            
            self._update_progress(100, "Complete!")
            self._log_message("Analysis completed successfully!")
            
            self.analysis_complete = True
            self.start_btn.configure(state="normal")
            self.export_btn.configure(state="normal")
            
        except Exception as e:
            self._log_message(f"Error: {str(e)}")
            self.start_btn.configure(state="normal")
            messagebox.showerror("Error", f"Analysis failed: {str(e)}")
            
    def _load_attack_vectors(self):
        """Load attack vectors (from file or simulated)"""
        # In production, this would receive data from the client
        # For now, simulate some attack vectors
        return [
            AttackVector(
                id="AV001",
                name="SQL Injection",
                port=3306,
                protocol="TCP",
                description="Attempt SQL injection on MySQL port",
                mitre_technique="T1190",
                capec_id="CAPEC-66"
            ),
            AttackVector(
                id="AV002",
                name="SSH Brute Force",
                port=22,
                protocol="TCP",
                description="Brute force attack on SSH service",
                mitre_technique="T1110",
                capec_id="CAPEC-49"
            ),
            AttackVector(
                id="AV003",
                name="HTTP Vulnerabilities",
                port=80,
                protocol="TCP",
                description="Web application attacks",
                mitre_technique="T1190",
                capec_id="CAPEC-1"
            )
        ]
        
    def _display_server_info(self, server_info: ServerInfo):
        """Display server information in the tab"""
        self.server_info_text.delete("1.0", "end")
        
        info = f"""
═══════════════════════════════════════════════════
SERVER INFORMATION ANALYSIS
═══════════════════════════════════════════════════

Hostname: {server_info.hostname}
OS: {server_info.os_type} {server_info.os_version}
Kernel: {server_info.kernel_version}
Architecture: {server_info.architecture}

───────────────────────────────────────────────────
INSTALLED SOFTWARE ({len(server_info.installed_software)} packages)
───────────────────────────────────────────────────
"""
        for pkg in server_info.installed_software[:20]:  # Show first 20
            info += f"  • {pkg['name']} v{pkg.get('version', 'unknown')}\n"
        
        if len(server_info.installed_software) > 20:
            info += f"\n  ... and {len(server_info.installed_software) - 20} more packages\n"
            
        info += f"""
───────────────────────────────────────────────────
SECURITY MEASURES
───────────────────────────────────────────────────
Firewall: {'Active' if server_info.security_measures.get('firewall_active') else 'Inactive'}
SELinux/AppArmor: {server_info.security_measures.get('selinux_status', 'Unknown')}
Fail2Ban: {'Active' if server_info.security_measures.get('fail2ban_active') else 'Inactive'}

───────────────────────────────────────────────────
INFRASTRUCTURE
───────────────────────────────────────────────────
Database Servers: {', '.join(server_info.infrastructure.get('databases', ['None'])) or 'None'}
Web Servers: {', '.join(server_info.infrastructure.get('web_servers', ['None'])) or 'None'}
Open Ports: {len(server_info.open_ports)} ports detected
"""
        self.server_info_text.insert("1.0", info)
        
    def _display_vulnerabilities(self, vulnerabilities):
        """Display vulnerabilities in the tab"""
        self.vuln_text.delete("1.0", "end")
        self.all_vulnerabilities = vulnerabilities
        
        self._filter_vulnerabilities("All")
        
    def _filter_vulnerabilities(self, severity):
        """Filter vulnerabilities by severity"""
        self.vuln_text.delete("1.0", "end")
        
        filtered = self.all_vulnerabilities if severity == "All" else \
                   [v for v in self.all_vulnerabilities if v.severity == severity.lower()]
        
        if not filtered:
            self.vuln_text.insert("1.0", "No vulnerabilities found.\n")
            return
            
        info = f"""
═══════════════════════════════════════════════════
VULNERABILITIES ({len(filtered)} found)
═══════════════════════════════════════════════════
"""
        for vuln in filtered:
            severity_colors = {
                'critical': '🔴',
                'high': '🟠',
                'medium': '🟡',
                'low': '🟢'
            }
            icon = severity_colors.get(vuln.severity, '⚪')
            
            info += f"""
{icon} [{vuln.severity.upper()}] {vuln.cve_id or 'N/A'}
   Title: {vuln.title}
   CWE: {vuln.cwe_id or 'N/A'}
   CVSS Score: {vuln.cvss_score or 'N/A'}
   Description: {vuln.description[:100]}...
   Affected Software: {vuln.affected_software}
   
"""
        self.vuln_text.insert("1.0", info)
        
    def _display_attack_vectors(self, attack_vectors):
        """Display attack vectors in the tab"""
        self.attack_text.delete("1.0", "end")
        self.all_attack_vectors = attack_vectors
        
        self._filter_attacks("All")
        
    def _filter_attacks(self, filter_type):
        """Filter attack vectors by realizability"""
        self.attack_text.delete("1.0", "end")
        
        if filter_type == "All":
            filtered = self.all_attack_vectors
        elif filter_type == "Realizable":
            filtered = [a for a in self.all_attack_vectors if a.is_realizable]
        else:  # Not Realizable
            filtered = [a for a in self.all_attack_vectors if not a.is_realizable]
        
        if not filtered:
            self.attack_text.insert("1.0", "No attack vectors found.\n")
            return
            
        info = f"""
═══════════════════════════════════════════════════
ATTACK VECTORS ({len(filtered)} found)
═══════════════════════════════════════════════════
"""
        for attack in filtered:
            status = "✅ REALIZABLE" if attack.is_realizable else "❌ NOT REALIZABLE"
            reason = f"\n   Reason: {attack.realizability_reason}" if not attack.is_realizable else ""
            
            info += f"""
{status}
ID: {attack.id}
Name: {attack.name}
Port: {attack.port}/{attack.protocol}
MITRE ATT&CK: {attack.mitre_technique or 'N/A'}
CAPEC: {attack.capec_id or 'N/A'}
Description: {attack.description}
{reason}
───────────────────────────────────────────────────
"""
        self.attack_text.insert("1.0", info)
        
    def _display_recommendations(self, report: SecurityReport):
        """Display recommendations in the tab"""
        self.recommendations_text.delete("1.0", "end")
        
        info = f"""
═══════════════════════════════════════════════════
SECURITY RECOMMENDATIONS
═══════════════════════════════════════════════════

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

SUMMARY:
  Total Vulnerabilities: {report.total_vulnerabilities}
  Critical: {report.critical_count}
  High: {report.high_count}
  Medium: {report.medium_count}
  Low: {report.low_count}
  
  Realizable Attacks: {report.realizable_attacks}
  Non-Realizable Attacks: {report.non_realizable_attacks}

═══════════════════════════════════════════════════
PRIORITY ACTIONS
═══════════════════════════════════════════════════
"""
        for i, rec in enumerate(report.recommendations[:10], 1):
            info += f"""
{i}. {rec['title']}
   Priority: {rec['priority']}
   Description: {rec['description']}
   Implementation: {rec['implementation_steps']}
   Related CVEs: {', '.join(rec.get('related_cves', [])) or 'N/A'}
   
"""
        if len(report.recommendations) > 10:
            info += f"\n... and {len(report.recommendations) - 10} more recommendations\n"
            
        self.recommendations_text.insert("1.0", info)
        
    def _export_report(self):
        """Export report to file"""
        if not self.current_report:
            messagebox.showwarning("Warning", "No report to export. Run analysis first.")
            return
            
        filetypes = [
            ("JSON files", "*.json"),
            ("HTML files", "*.html"),
            ("Text files", "*.txt"),
            ("All files", "*.*")
        ]
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=filetypes,
            initialfile=f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )
        
        if filename:
            try:
                ext = os.path.splitext(filename)[1].lower()
                
                if ext == ".json":
                    self.report_gen.generate_json_report(self.current_report, filename)
                elif ext == ".html":
                    self.report_gen.generate_html_report(self.current_report, filename)
                elif ext == ".txt":
                    self.report_gen.generate_text_report(self.current_report, filename)
                else:
                    self.report_gen.generate_json_report(self.current_report, filename)
                    
                self._log_message(f"Report exported to: {filename}")
                messagebox.showinfo("Success", f"Report saved to:\n{filename}")
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export report: {str(e)}")
                
    def _clear_results(self):
        """Clear all results and reset"""
        if messagebox.askyesno("Confirm", "Clear all analysis results?"):
            self.server_info_text.delete("1.0", "end")
            self.vuln_text.delete("1.0", "end")
            self.attack_text.delete("1.0", "end")
            self.recommendations_text.delete("1.0", "end")
            self.log_text.delete("1.0", "end")
            self.progress_bar.set(0)
            self.progress_label.configure(text="Progress: 0%")
            self.current_report = None
            self.analysis_complete = False
            self.start_btn.configure(state="normal")
            self.export_btn.configure(state="disabled")
            self._log_message("Results cleared. Ready for new analysis.")


def main():
    app = ServerGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
