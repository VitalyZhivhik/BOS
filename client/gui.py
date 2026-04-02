#!/usr/bin/env python3
"""
Client GUI Application for BOS (Security Analysis System)
Scans target servers and sends attack vectors to server
"""

import customtkinter as ctk
from tkinter import messagebox, filedialog
import threading
import json
import os
import sys
from datetime import datetime
import ipaddress

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.models import AttackVector, ScanResult
from client.scanner.port_scanner import PortScanner


class ClientGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        # Configure window
        self.title("BOS Client - Attack Vector Scanner")
        self.geometry("1000x700")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        # Initialize scanner
        self.scanner = PortScanner()
        
        self.scan_complete = False
        self.current_results = None
        
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
            text="🎯 BOS Client - Attack Vector Scanner",
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
        
        # Configuration panel
        self.config_frame = ctk.CTkFrame(self.main_frame)
        self.config_frame.pack(fill="x", pady=10)
        
        # Target configuration
        self.target_frame = ctk.CTkFrame(self.config_frame)
        self.target_frame.pack(fill="x", padx=10, pady=10)
        
        ctk.CTkLabel(
            self.target_frame,
            text="Target Configuration:",
            font=ctk.CTkFont(weight="bold", size=16)
        ).pack(anchor="w", pady=5)
        
        # Target IP/Hostname
        self.ip_frame = ctk.CTkFrame(self.target_frame)
        self.ip_frame.pack(fill="x", pady=5)
        
        ctk.CTkLabel(self.ip_frame, text="Target IP/Hostname:", width=150).pack(side="left", padx=5)
        self.target_ip = ctk.CTkEntry(self.ip_frame, placeholder_text="192.168.1.1", width=300)
        self.target_ip.pack(side="left", padx=5)
        
        # Port range
        self.port_frame = ctk.CTkFrame(self.target_frame)
        self.port_frame.pack(fill="x", pady=5)
        
        ctk.CTkLabel(self.port_frame, text="Port Range:", width=150).pack(side="left", padx=5)
        self.port_start = ctk.CTkEntry(self.port_frame, placeholder_text="1", width=100)
        self.port_start.pack(side="left", padx=5)
        ctk.CTkLabel(self.port_frame, text="-").pack(side="left", padx=5)
        self.port_end = ctk.CTkEntry(self.port_frame, placeholder_text="1000", width=100)
        self.port_end.pack(side="left", padx=5)
        
        # Scan type
        self.scan_type_frame = ctk.CTkFrame(self.target_frame)
        self.scan_type_frame.pack(fill="x", pady=5)
        
        ctk.CTkLabel(self.scan_type_frame, text="Scan Type:", width=150).pack(side="left", padx=5)
        self.scan_type_var = ctk.StringVar(value="TCP Connect")
        self.scan_type_menu = ctk.CTkOptionMenu(
            self.scan_type_frame,
            variable=self.scan_type_var,
            values=["TCP Connect", "SYN Scan", "UDP Scan", "Service Detection"]
        )
        self.scan_type_menu.pack(side="left", padx=5)
        
        # Control buttons
        self.button_frame = ctk.CTkFrame(self.config_frame)
        self.button_frame.pack(fill="x", padx=10, pady=10)
        
        self.start_btn = ctk.CTkButton(
            self.button_frame,
            text="🚀 Start Scan",
            command=self._start_scan,
            height=40,
            font=ctk.CTkFont(size=16),
            fg_color="green"
        )
        self.start_btn.pack(side="left", padx=10)
        
        self.stop_btn = ctk.CTkButton(
            self.button_frame,
            text="⏹️ Stop Scan",
            command=self._stop_scan,
            state="disabled",
            height=40,
            font=ctk.CTkFont(size=16),
            fg_color="red"
        )
        self.stop_btn.pack(side="left", padx=10)
        
        self.export_btn = ctk.CTkButton(
            self.button_frame,
            text="💾 Export Results",
            command=self._export_results,
            state="disabled",
            height=40,
            font=ctk.CTkFont(size=16)
        )
        self.export_btn.pack(side="left", padx=10)
        
        self.send_btn = ctk.CTkButton(
            self.button_frame,
            text="📤 Send to Server",
            command=self._send_to_server,
            state="disabled",
            height=40,
            font=ctk.CTkFont(size=16),
            fg_color="orange"
        )
        self.send_btn.pack(side="left", padx=10)
        
        # Progress section
        self.progress_frame = ctk.CTkFrame(self.main_frame)
        self.progress_frame.pack(fill="x", pady=10)
        
        self.progress_bar = ctk.CTkProgressBar(self.progress_frame)
        self.progress_bar.pack(fill="x", padx=20, pady=10)
        self.progress_bar.set(0)
        
        self.progress_label = ctk.CTkLabel(
            self.progress_frame,
            text="Progress: 0% - Ready",
            font=ctk.CTkFont(size=12)
        )
        self.progress_label.pack()
        
        self.stats_label = ctk.CTkLabel(
            self.progress_frame,
            text="Ports scanned: 0 | Open: 0 | Filtered: 0 | Closed: 0",
            font=ctk.CTkFont(size=11),
            text_color="gray"
        )
        self.stats_label.pack(pady=5)
        
        # Results notebook (tabs)
        self.notebook = ctk.CTkTabview(self.main_frame)
        self.notebook.pack(fill="both", expand=True, pady=10)
        
        # Tab 1: Open Ports
        self.open_ports_tab = self.notebook.add("Open Ports")
        self._create_open_ports_tab()
        
        # Tab 2: Attack Vectors
        self.attack_vectors_tab = self.notebook.add("Attack Vectors")
        self._create_attack_vectors_tab()
        
        # Tab 3: Services
        self.services_tab = self.notebook.add("Services")
        self._create_services_tab()
        
        # Log panel
        self.log_frame = ctk.CTkFrame(self.main_frame, height=120)
        self.log_frame.pack(fill="x", pady=10)
        
        self.log_label = ctk.CTkLabel(
            self.log_frame,
            text="Activity Log:",
            font=ctk.CTkFont(weight="bold")
        )
        self.log_label.pack(anchor="w", padx=10, pady=5)
        
        self.log_text = ctk.CTkTextbox(self.log_frame, height=80)
        self.log_text.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.scan_thread = None
        self.scan_running = False
        
    def _create_open_ports_tab(self):
        """Create open ports tab"""
        # Filter frame
        self.ports_filter_frame = ctk.CTkFrame(self.open_ports_tab)
        self.ports_filter_frame.pack(fill="x", padx=10, pady=5)
        
        ctk.CTkLabel(self.ports_filter_frame, text="Filter by protocol:").pack(side="left", padx=5)
        
        self.protocol_var = ctk.StringVar(value="All")
        self.protocol_menu = ctk.CTkOptionMenu(
            self.ports_filter_frame,
            variable=self.protocol_var,
            values=["All", "TCP", "UDP"],
            command=self._filter_ports
        )
        self.protocol_menu.pack(side="left", padx=5)
        
        # Ports list
        self.ports_text = ctk.CTkTextbox(self.open_ports_tab)
        self.ports_text.pack(fill="both", expand=True, padx=10, pady=10)
        
    def _create_attack_vectors_tab(self):
        """Create attack vectors tab"""
        self.attack_text = ctk.CTkTextbox(self.attack_vectors_tab)
        self.attack_text.pack(fill="both", expand=True, padx=10, pady=10)
        
    def _create_services_tab(self):
        """Create services tab"""
        self.services_text = ctk.CTkTextbox(self.services_tab)
        self.services_text.pack(fill="both", expand=True, padx=10, pady=10)
        
    def _log_message(self, message):
        """Add message to log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert("end", f"[{timestamp}] {message}\n")
        self.log_text.see("end")
        self.update_idletasks()
        
    def _update_progress(self, value, label=""):
        """Update progress bar"""
        self.progress_bar.set(value / 100)
        self.progress_label.configure(text=f"Progress: {value}% {label}")
        self.update_idletasks()
        
    def _update_stats(self, scanned, open_count, filtered, closed):
        """Update scan statistics"""
        self.stats_label.configure(
            text=f"Ports scanned: {scanned} | Open: {open_count} | Filtered: {filtered} | Closed: {closed}"
        )
        self.update_idletasks()
        
    def _validate_target(self, target):
        """Validate target IP or hostname"""
        if not target:
            return False, "Target IP/hostname is required"
            
        try:
            # Try to parse as IP address
            ipaddress.ip_address(target)
            return True, ""
        except ValueError:
            # Might be a hostname - basic validation
            if len(target) > 3 and '.' in target:
                return True, ""
            return False, "Invalid IP address or hostname format"
            
    def _start_scan(self):
        """Start port scanning in background thread"""
        # Validate input
        target = self.target_ip.get().strip()
        valid, error = self._validate_target(target)
        
        if not valid:
            messagebox.showerror("Validation Error", error)
            return
            
        # Get port range
        try:
            port_start = int(self.port_start.get().strip() or "1")
            port_end = int(self.port_end.get().strip() or "1000")
            
            if port_start < 1 or port_end > 65535 or port_start > port_end:
                raise ValueError("Invalid port range")
        except ValueError as e:
            messagebox.showerror("Validation Error", f"Invalid port range: {str(e)}")
            return
            
        # Disable start button, enable stop button
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.scan_complete = False
        
        self._log_message(f"Starting scan on {target}:{port_start}-{port_end}")
        self._log_message(f"Scan type: {self.scan_type_var.get()}")
        self._update_progress(0, "Initializing...")
        
        # Start scan in background thread
        self.scan_running = True
        self.scan_thread = threading.Thread(
            target=self._run_scan,
            args=(target, port_start, port_end),
            daemon=True
        )
        self.scan_thread.start()
        
    def _run_scan(self, target, port_start, port_end):
        """Run the port scan"""
        try:
            total_ports = port_end - port_start + 1
            scanned = 0
            open_ports = []
            filtered = 0
            closed = 0
            
            # Perform scan
            self._log_message("Scanning ports...")
            
            scan_result = self.scanner.scan(
                target=target,
                port_start=port_start,
                port_end=port_end,
                scan_type=self.scan_type_var.get().lower(),
                callback=lambda s, o, f, c: self._update_stats(s, o, f, c)
            )
            
            self.current_results = scan_result
            
            # Update UI with results
            self._display_open_ports(scan_result.open_ports)
            self._generate_attack_vectors(scan_result)
            self._display_services(scan_result.services)
            
            self._update_progress(100, "Scan Complete!")
            self._log_message(f"Scan completed. Found {len(scan_result.open_ports)} open ports.")
            
            self.scan_complete = True
            self.scan_running = False
            self.start_btn.configure(state="normal")
            self.stop_btn.configure(state="disabled")
            self.export_btn.configure(state="normal")
            self.send_btn.configure(state="normal")
            
        except Exception as e:
            self._log_message(f"Error: {str(e)}")
            self.scan_running = False
            self.start_btn.configure(state="normal")
            self.stop_btn.configure(state="disabled")
            messagebox.showerror("Scan Error", f"Scan failed: {str(e)}")
            
    def _stop_scan(self):
        """Stop the current scan"""
        if self.scan_running:
            if messagebox.askyesno("Confirm", "Stop the current scan?"):
                self.scan_running = False
                self.scanner.stop_scan()
                self._log_message("Scan stopped by user")
                self.start_btn.configure(state="normal")
                self.stop_btn.configure(state="disabled")
                
    def _display_open_ports(self, open_ports):
        """Display open ports in the tab"""
        self.ports_text.delete("1.0", "end")
        self.all_ports = open_ports
        
        self._filter_ports("All")
        
    def _filter_ports(self, protocol):
        """Filter ports by protocol"""
        self.ports_text.delete("1.0", "end")
        
        if not hasattr(self, 'all_ports'):
            self.ports_text.insert("1.0", "No ports scanned yet.\n")
            return
            
        filtered = self.all_ports if protocol == "All" else \
                   [p for p in self.all_ports if p['protocol'].upper() == protocol.upper()]
        
        if not filtered:
            self.ports_text.insert("1.0", "No open ports found.\n")
            return
            
        info = f"""
═══════════════════════════════════════════════════
OPEN PORTS ({len(filtered)} found)
═══════════════════════════════════════════════════

PORT       PROTOCOL  STATE    SERVICE
───────────────────────────────────────────────────
"""
        for port in filtered:
            info += f"{port['port']:<10} {port['protocol']:<9} {port['state']:<8} {port.get('service', 'unknown')}\n"
            
        self.ports_text.insert("1.0", info)
        
    def _generate_attack_vectors(self, scan_result: ScanResult):
        """Generate attack vectors based on scan results"""
        self.attack_text.delete("1.0", "end")
        
        if not scan_result.open_ports:
            self.attack_text.insert("1.0", "No attack vectors generated - no open ports found.\n")
            return
            
        attack_vectors = self.scanner.identify_attack_vectors(scan_result)
        self.current_attack_vectors = attack_vectors
        
        info = f"""
═══════════════════════════════════════════════════
IDENTIFIED ATTACK VECTORS ({len(attack_vectors)})
═══════════════════════════════════════════════════

"""
        for av in attack_vectors:
            info += f"""
🎯 {av.name}
   Port: {av.port}/{av.protocol}
   MITRE ATT&CK: {av.mitre_technique or 'N/A'}
   CAPEC: {av.capec_id or 'N/A'}
   Description: {av.description}
   Risk Level: {av.risk_level or 'Unknown'}
   
───────────────────────────────────────────────────
"""
        self.attack_text.insert("1.0", info)
        
    def _display_services(self, services):
        """Display detected services"""
        self.services_text.delete("1.0", "end")
        
        if not services:
            self.services_text.insert("1.0", "No services detected.\n")
            return
            
        info = f"""
═══════════════════════════════════════════════════
DETECTED SERVICES ({len(services)})
═══════════════════════════════════════════════════

SERVICE              PORT    PROTOCOL  VERSION/BANNER
────────────────────────────────────────────────────────────
"""
        for service in services:
            version = service.get('version', 'unknown') or 'unknown'
            banner = service.get('banner', '')[:50]
            info += f"{service.get('name', 'unknown'):<20} {service['port']:<7} {service['protocol']:<9} {version}\n"
            if banner:
                info += f"   Banner: {banner}...\n"
                
        self.services_text.insert("1.0", info)
        
    def _export_results(self):
        """Export scan results to file"""
        if not self.current_results:
            messagebox.showwarning("Warning", "No results to export. Run a scan first.")
            return
            
        filetypes = [
            ("JSON files", "*.json"),
            ("Text files", "*.txt"),
            ("All files", "*.*")
        ]
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=filetypes,
            initialfile=f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )
        
        if filename:
            try:
                ext = os.path.splitext(filename)[1].lower()
                
                if ext == ".json":
                    with open(filename, 'w') as f:
                        json.dump(self.current_results.to_dict(), f, indent=2)
                else:
                    # Text format
                    with open(filename, 'w') as f:
                        f.write(str(self.current_results))
                    
                self._log_message(f"Results exported to: {filename}")
                messagebox.showinfo("Success", f"Results saved to:\n{filename}")
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export results: {str(e)}")
                
    def _send_to_server(self):
        """Send attack vectors to server"""
        if not self.current_attack_vectors:
            messagebox.showwarning("Warning", "No attack vectors to send.")
            return
            
        # In production, this would send to the server via API
        # For now, save to file that server can read
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON files", "*.json")],
                initialfile=f"attack_vectors_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                title="Save Attack Vectors for Server"
            )
            
            if filename:
                data = {
                    "timestamp": datetime.now().isoformat(),
                    "target": self.target_ip.get(),
                    "attack_vectors": [av.to_dict() for av in self.current_attack_vectors]
                }
                
                with open(filename, 'w') as f:
                    json.dump(data, f, indent=2)
                    
                self._log_message(f"Attack vectors saved to: {filename}")
                messagebox.showinfo(
                    "Success",
                    f"Attack vectors saved to:\n{filename}\n\n"
                    f"Copy this file to the server for analysis."
                )
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save attack vectors: {str(e)}")


def main():
    app = ClientGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
