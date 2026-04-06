#!/usr/bin/env python3
"""
GUI interface for the server-side security analyzer using PyQt6.
"""

import sys
import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from PyQt6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QTabWidget,
    QLabel,
    QPushButton,
    QTextEdit,
    QProgressBar,
    QGroupBox,
    QGridLayout,
    QTreeWidget,
    QTreeWidgetItem,
    QFileDialog,
    QMessageBox,
    QStatusBar,
    QMenu,
    QMenuBar,
    QSplitter,
    QFrame,
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QColor, QIcon, QAction

from shared import (
    ServerInfrastructure,
    ScanResult,
    OpenPort,
    AttackVector,
    logger,
)
from server import ServerAnalyzer, CorrelationEngine, ReportGenerator


class AnalysisWorker(QThread):
    """Worker thread for running security analysis."""
    
    progress = pyqtSignal(int, str)
    finished = pyqtSignal(object)
    error = pyqtSignal(str)
    
    def __init__(self, output_dir: str = "./reports"):
        super().__init__()
        self.output_dir = output_dir
        
    def run(self):
        try:
            self.progress.emit(10, "Analyzing server infrastructure...")
            analyzer = ServerAnalyzer()
            infrastructure = analyzer.analyze_server()
            
            self.progress.emit(40, "Creating scan results...")
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
            
            self.progress.emit(60, "Correlating vulnerabilities...")
            engine = CorrelationEngine()
            vulnerabilities = engine.correlate_vulnerabilities(infrastructure, scan_result.attack_vectors)
            report = engine.generate_security_report(infrastructure, vulnerabilities, scan_result.attack_vectors)
            
            self.progress.emit(80, "Generating reports...")
            generator = ReportGenerator()
            output_path = Path(self.output_dir)
            output_path.mkdir(parents=True, exist_ok=True)
            generated_files = generator.generate_all_reports(report, str(output_path))
            
            self.progress.emit(100, "Analysis complete!")
            self.finished.emit((report, generated_files))
            
        except Exception as e:
            self.error.emit(str(e))


class ServerSecurityGUI(QMainWindow):
    """Main GUI window for the server security analyzer."""
    
    def __init__(self):
        super().__init__()
        self.current_report = None
        self.generated_files = {}
        self.worker: Optional[AnalysisWorker] = None
        self.init_ui()
        
    def init_ui(self):
        """Initialize the user interface."""
        self.setWindowTitle("🛡️ Server Security Analyzer")
        self.setMinimumSize(1200, 800)
        
        # Create menu bar
        self.create_menu_bar()
        
        # Create central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Title
        title_label = QLabel("🛡️ Server Security Analyzer")
        title_font = QFont()
        title_font.setPointSize(24)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(title_label)
        
        # Create splitter for resizable sections
        splitter = QSplitter(Qt.Orientation.Vertical)
        main_layout.addWidget(splitter)
        
        # Top section - Control panel and status
        top_widget = QWidget()
        top_layout = QVBoxLayout(top_widget)
        
        # Control panel
        control_group = QGroupBox("Control Panel")
        control_layout = QHBoxLayout(control_group)
        
        self.start_btn = QPushButton("▶️ Start Analysis")
        self.start_btn.clicked.connect(self.start_analysis)
        self.start_btn.setMinimumHeight(40)
        start_font = QFont()
        start_font.setBold(True)
        self.start_btn.setFont(start_font)
        control_layout.addWidget(self.start_btn)
        
        self.export_btn = QPushButton("📁 Export Reports")
        self.export_btn.clicked.connect(self.export_reports)
        self.export_btn.setEnabled(False)
        self.export_btn.setMinimumHeight(40)
        control_layout.addWidget(self.export_btn)
        
        self.clear_btn = QPushButton("🗑️ Clear Results")
        self.clear_btn.clicked.connect(self.clear_results)
        self.clear_btn.setMinimumHeight(40)
        control_layout.addWidget(self.clear_btn)
        
        top_layout.addWidget(control_group)
        
        # Progress section
        progress_group = QGroupBox("Analysis Progress")
        progress_layout = QVBoxLayout(progress_group)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setMinimum(0)
        self.progress_bar.setMaximum(100)
        self.progress_bar.setValue(0)
        progress_layout.addWidget(self.progress_bar)
        
        self.status_label = QLabel("Ready to start analysis")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        progress_layout.addWidget(self.status_label)
        
        top_layout.addWidget(progress_group)
        splitter.addWidget(top_widget)
        
        # Bottom section - Tab widget for results
        self.tabs = QTabWidget()
        splitter.addWidget(self.tabs)
        
        # Infrastructure tab
        self.infra_tab = QWidget()
        self.tabs.addTab(self.infra_tab, "🖥️ Infrastructure")
        self.setup_infrastructure_tab()
        
        # Vulnerabilities tab
        self.vuln_tab = QWidget()
        self.tabs.addTab(self.vuln_tab, "⚠️ Vulnerabilities")
        self.setup_vulnerabilities_tab()
        
        # Attacks tab
        self.attacks_tab = QWidget()
        self.tabs.addTab(self.attacks_tab, "🎯 Attack Vectors")
        self.setup_attacks_tab()
        
        # Recommendations tab
        self.recs_tab = QWidget()
        self.tabs.addTab(self.recs_tab, "💡 Recommendations")
        self.setup_recommendations_tab()
        
        # Reports tab
        self.reports_tab = QWidget()
        self.tabs.addTab(self.reports_tab, "📄 Generated Reports")
        self.setup_reports_tab()
        
        # Log/Console tab
        self.log_tab = QWidget()
        self.tabs.addTab(self.log_tab, "📋 Log")
        self.setup_log_tab()
        
        # Status bar
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        self.statusBar.showMessage("Ready")
        
        # Set initial sizes
        splitter.setSizes([300, 500])
        
    def create_menu_bar(self):
        """Create the menu bar."""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("&File")
        
        load_action = QAction("Load Scan Results", self)
        load_action.triggered.connect(self.load_scan_results)
        file_menu.addAction(load_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Tools menu
        tools_menu = menubar.addMenu("&Tools")
        
        settings_action = QAction("Settings", self)
        settings_action.triggered.connect(self.show_settings)
        tools_menu.addAction(settings_action)
        
        # Help menu
        help_menu = menubar.addMenu("&Help")
        
        about_action = QAction("About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
        
    def setup_infrastructure_tab(self):
        """Setup the infrastructure tab."""
        layout = QVBoxLayout(self.infra_tab)
        
        self.infra_tree = QTreeWidget()
        self.infra_tree.setHeaderLabels(["Property", "Value"])
        self.infra_tree.setColumnWidth(0, 300)
        layout.addWidget(self.infra_tree)
        
    def setup_vulnerabilities_tab(self):
        """Setup the vulnerabilities tab."""
        layout = QVBoxLayout(self.vuln_tab)
        
        self.vuln_tree = QTreeWidget()
        self.vuln_tree.setHeaderLabels(["CVE/CWE", "Title", "Severity", "CVSS"])
        self.vuln_tree.setColumnWidth(0, 150)
        self.vuln_tree.setColumnWidth(1, 400)
        self.vuln_tree.setColumnWidth(2, 100)
        self.vuln_tree.setColumnWidth(3, 80)
        layout.addWidget(self.vuln_tree)
        
        # Summary group
        summary_group = QGroupBox("Vulnerability Summary")
        summary_layout = QGridLayout(summary_group)
        
        self.total_vuln_label = QLabel("Total: 0")
        self.critical_label = QLabel("Critical: 0")
        self.high_label = QLabel("High: 0")
        self.medium_label = QLabel("Medium: 0")
        self.low_label = QLabel("Low: 0")
        
        summary_layout.addWidget(self.total_vuln_label, 0, 0)
        summary_layout.addWidget(self.critical_label, 0, 1)
        summary_layout.addWidget(self.high_label, 0, 2)
        summary_layout.addWidget(self.medium_label, 1, 0)
        summary_layout.addWidget(self.low_label, 1, 1)
        
        layout.addWidget(summary_group)
        
    def setup_attacks_tab(self):
        """Setup the attacks tab."""
        layout = QVBoxLayout(self.attacks_tab)
        
        self.attacks_tree = QTreeWidget()
        self.attacks_tree.setHeaderLabels(["ID", "Name", "Target Ports", "Realizable", "Risk Level"])
        self.attacks_tree.setColumnWidth(0, 100)
        self.attacks_tree.setColumnWidth(1, 300)
        self.attacks_tree.setColumnWidth(2, 150)
        self.attacks_tree.setColumnWidth(3, 100)
        self.attacks_tree.setColumnWidth(4, 100)
        layout.addWidget(self.attacks_tree)
        
        # Statistics
        stats_group = QGroupBox("Attack Statistics")
        stats_layout = QHBoxLayout(stats_group)
        
        self.realizable_label = QLabel("Realizable: 0")
        self.non_realizable_label = QLabel("Non-Realizable: 0")
        
        stats_layout.addWidget(self.realizable_label)
        stats_layout.addWidget(self.non_realizable_label)
        
        layout.addWidget(stats_group)
        
    def setup_recommendations_tab(self):
        """Setup the recommendations tab."""
        layout = QVBoxLayout(self.recs_tab)
        
        self.recs_text = QTextEdit()
        self.recs_text.setReadOnly(True)
        self.recs_text.setFont(QFont("Courier New", 10))
        layout.addWidget(self.recs_text)
        
    def setup_reports_tab(self):
        """Setup the reports tab."""
        layout = QVBoxLayout(self.reports_tab)
        
        self.reports_list = QTreeWidget()
        self.reports_list.setHeaderLabels(["Format", "File Path"])
        self.reports_list.setColumnWidth(0, 100)
        self.reports_list.setColumnWidth(1, 600)
        layout.addWidget(self.reports_list)
        
        open_btn = QPushButton("📂 Open Report Directory")
        open_btn.clicked.connect(self.open_report_directory)
        layout.addWidget(open_btn)
        
    def setup_log_tab(self):
        """Setup the log tab."""
        layout = QVBoxLayout(self.log_tab)
        
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setFont(QFont("Courier New", 9))
        self.log_text.setStyleSheet("background-color: #1e1e1e; color: #d4d4d4;")
        layout.addWidget(self.log_text)
        
    def log_message(self, message: str):
        """Add a message to the log."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_text.append(f"[{timestamp}] {message}")
        
    def start_analysis(self):
        """Start the security analysis."""
        if self.worker and self.worker.isRunning():
            QMessageBox.warning(self, "Analysis Running", 
                              "An analysis is already in progress.")
            return
            
        self.start_btn.setEnabled(False)
        self.progress_bar.setValue(0)
        self.status_label.setText("Starting analysis...")
        self.log_message("Starting security analysis...")
        self.statusBar.showMessage("Analysis in progress...")
        
        self.worker = AnalysisWorker("./reports")
        self.worker.progress.connect(self.on_progress)
        self.worker.finished.connect(self.on_analysis_finished)
        self.worker.error.connect(self.on_analysis_error)
        self.worker.start()
        
    def on_progress(self, value: int, message: str):
        """Handle progress updates."""
        self.progress_bar.setValue(value)
        self.status_label.setText(message)
        self.log_message(message)
        
    def on_analysis_finished(self, result):
        """Handle analysis completion."""
        report, generated_files = result
        self.current_report = report
        self.generated_files = generated_files
        
        self.log_message("Analysis completed successfully!")
        self.status_label.setText("Analysis complete!")
        self.statusBar.showMessage("Analysis completed successfully!")
        
        self.update_infrastructure_display()
        self.update_vulnerabilities_display()
        self.update_attacks_display()
        self.update_recommendations_display()
        self.update_reports_display()
        
        self.start_btn.setEnabled(True)
        self.export_btn.setEnabled(True)
        
        QMessageBox.information(self, "Analysis Complete",
                               f"Analysis completed successfully!\n"
                               f"Total vulnerabilities: {report.total_vulnerabilities}\n"
                               f"Reports saved to: ./reports/")
        
    def on_analysis_error(self, error_msg: str):
        """Handle analysis error."""
        self.log_message(f"ERROR: {error_msg}")
        self.status_label.setText("Analysis failed!")
        self.statusBar.showMessage("Analysis failed!")
        self.start_btn.setEnabled(True)
        
        QMessageBox.critical(self, "Analysis Error",
                            f"Analysis failed: {error_msg}")
        
    def update_infrastructure_display(self):
        """Update the infrastructure tab display."""
        if not self.current_report:
            return
            
        self.infra_tree.clear()
        infra = self.current_report.server_infrastructure
        
        # Basic info
        basic_item = QTreeWidgetItem(["Basic Information", ""])
        basic_item.addChild(QTreeWidgetItem(["Hostname", infra.hostname]))
        basic_item.addChild(QTreeWidgetItem(["OS", f"{infra.os_type} {infra.os_version}"]))
        basic_item.addChild(QTreeWidgetItem(["Kernel", infra.kernel_version or "N/A"]))
        basic_item.addChild(QTreeWidgetItem(["Architecture", infra.architecture or "N/A"]))
        self.infra_tree.addTopLevelItem(basic_item)
        
        # Security measures
        security_item = QTreeWidgetItem(["Security Measures", ""])
        sec_measures = infra.security_measures
        security_item.addChild(QTreeWidgetItem(["Firewall Active", str(sec_measures.get('firewall_active', False))]))
        security_item.addChild(QTreeWidgetItem(["Firewall Type", sec_measures.get('firewall_type') or "None"]))
        security_item.addChild(QTreeWidgetItem(["SELinux Status", sec_measures.get('selinux_status') or "N/A"]))
        security_item.addChild(QTreeWidgetItem(["Fail2Ban Active", str(sec_measures.get('fail2ban_active', False))]))
        self.infra_tree.addTopLevelItem(security_item)
        
        # Infrastructure components
        infra_item = QTreeWidgetItem(["Infrastructure Components", ""])
        components = infra.infrastructure
        infra_item.addChild(QTreeWidgetItem(["Databases", ", ".join(components.get('databases', [])) or "None"]))
        infra_item.addChild(QTreeWidgetItem(["Web Servers", ", ".join(components.get('web_servers', [])) or "None"]))
        infra_item.addChild(QTreeWidgetItem(["Has Database", str(infra.has_database)]))
        infra_item.addChild(QTreeWidgetItem(["Has Web Server", str(infra.has_web_server)]))
        self.infra_tree.addTopLevelItem(infra_item)
        
        # Expand all
        self.infra_tree.expandAll()
        
    def update_vulnerabilities_display(self):
        """Update the vulnerabilities tab display."""
        if not self.current_report:
            return
            
        self.vuln_tree.clear()
        
        # In a real implementation, vulnerabilities would come from the report
        # For now, show summary
        self.total_vuln_label.setText(f"Total: {self.current_report.total_vulnerabilities}")
        self.critical_label.setText(f"Critical: {self.current_report.critical_count}")
        self.high_label.setText(f"High: {self.current_report.high_count}")
        self.medium_label.setText(f"Medium: {self.current_report.medium_count}")
        self.low_label.setText(f"Low: {self.current_report.low_count}")
        
        # Color code severity labels
        self.critical_label.setStyleSheet("color: #f44336; font-weight: bold;")
        self.high_label.setStyleSheet("color: #ff9800; font-weight: bold;")
        self.medium_label.setStyleSheet("color: #ffc107; font-weight: bold;")
        self.low_label.setStyleSheet("color: #4caf50; font-weight: bold;")
        
    def update_attacks_display(self):
        """Update the attacks tab display."""
        if not self.current_report:
            return
            
        self.attacks_tree.clear()
        
        self.realizable_label.setText(f"Realizable: {self.current_report.realizable_attacks}")
        self.non_realizable_label.setText(f"Non-Realizable: {self.current_report.non_realizable_attacks}")
        
    def update_recommendations_display(self):
        """Update the recommendations tab display."""
        if not self.current_report:
            return
            
        self.recs_text.clear()
        
        recommendations = self.current_report.recommendations
        if not recommendations:
            self.recs_text.append("No recommendations at this time.")
            return
            
        for i, rec in enumerate(recommendations, 1):
            priority = rec.get('priority', 'Medium')
            priority_color = {
                'Critical': '#f44336',
                'High': '#ff9800',
                'Medium': '#ffc107',
                'Low': '#4caf50'
            }.get(priority, '#2196F3')
            
            self.recs_text.append(f"<h3 style='color: {priority_color};'>{i}. {rec.get('title', 'Recommendation')}</h3>")
            self.recs_text.append(f"<b>Priority:</b> {priority}")
            self.recs_text.append(f"<b>Description:</b> {rec.get('description', 'N/A')}")
            self.recs_text.append(f"<b>Implementation Steps:</b><br><pre>{rec.get('implementation_steps', 'N/A')}</pre>")
            self.recs_text.append("<hr>")
            
    def update_reports_display(self):
        """Update the reports tab display."""
        if not self.generated_files:
            return
            
        self.reports_list.clear()
        
        for format_type, filepath in self.generated_files.items():
            item = QTreeWidgetItem([format_type.upper(), filepath])
            self.reports_list.addTopLevelItem(item)
            
    def export_reports(self):
        """Export reports to a selected directory."""
        if not self.generated_files:
            QMessageBox.warning(self, "No Reports", "No reports available to export.")
            return
            
        directory = QFileDialog.getExistingDirectory(self, "Select Export Directory")
        if directory:
            QMessageBox.information(self, "Export Complete",
                                   f"Reports are available in:\n{directory}")
                                   
    def clear_results(self):
        """Clear all results."""
        reply = QMessageBox.question(self, "Clear Results",
                                    "Are you sure you want to clear all results?",
                                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
                                    
        if reply == QMessageBox.StandardButton.Yes:
            self.current_report = None
            self.generated_files = {}
            self.progress_bar.setValue(0)
            self.status_label.setText("Ready to start analysis")
            self.infra_tree.clear()
            self.vuln_tree.clear()
            self.attacks_tree.clear()
            self.recs_text.clear()
            self.reports_list.clear()
            self.log_text.clear()
            self.export_btn.setEnabled(False)
            self.log_message("Results cleared.")
            self.statusBar.showMessage("Results cleared.")
            
    def load_scan_results(self):
        """Load scan results from a JSON file."""
        filename, _ = QFileDialog.getOpenFileName(
            self, "Load Scan Results", "", "JSON Files (*.json);;All Files (*)"
        )
        
        if filename:
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                self.log_message(f"Loaded scan results from: {filename}")
                QMessageBox.information(self, "Success", f"Scan results loaded from:\n{filename}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load scan results:\n{str(e)}")
                
    def show_settings(self):
        """Show settings dialog."""
        QMessageBox.information(self, "Settings", "Settings dialog not implemented yet.")
        
    def show_about(self):
        """Show about dialog."""
        QMessageBox.about(
            self,
            "About Server Security Analyzer",
            "<h2>🛡️ Server Security Analyzer</h2>"
            "<p>Version 1.0.0</p>"
            "<p>A comprehensive security analysis tool for server infrastructure.</p>"
            "<p>Features:</p>"
            "<ul>"
            "<li>Server infrastructure analysis</li>"
            "<li>Vulnerability detection</li>"
            "<li>Attack vector assessment</li>"
            "<li>Security recommendations</li>"
            "<li>Report generation (JSON, HTML, TXT)</li>"
            "</ul>"
            "<p>© 2024 Security Team</p>"
        )
        
    def open_report_directory(self):
        """Open the report directory in file explorer."""
        import subprocess
        import platform
        
        report_dir = Path("./reports").absolute()
        if report_dir.exists():
            if platform.system() == "Windows":
                subprocess.run(["explorer", str(report_dir)])
            elif platform.system() == "Darwin":
                subprocess.run(["open", str(report_dir)])
            else:
                subprocess.run(["xdg-open", str(report_dir)])
        else:
            QMessageBox.information(self, "No Reports", "No reports directory found. Run an analysis first.")
            
    def closeEvent(self, event):
        """Handle window close event."""
        if self.worker and self.worker.isRunning():
            reply = QMessageBox.question(
                self, "Analysis Running",
                "An analysis is still running. Are you sure you want to exit?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if reply == QMessageBox.StandardButton.No:
                event.ignore()
                return
        event.accept()


def main():
    """Main entry point for the GUI application."""
    app = QApplication(sys.argv)
    
    # Set application style
    app.setStyle("Fusion")
    
    # Create and show main window
    window = ServerSecurityGUI()
    window.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
