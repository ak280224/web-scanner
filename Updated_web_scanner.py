#!/usr/bin/env python3

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import requests
from urllib.parse import urljoin, urlparse, parse_qs, quote
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import json
import re
import socket
import hashlib
import ssl
from datetime import datetime
from threading import Thread, Lock, Event
from bs4 import BeautifulSoup
from collections import defaultdict
import base64
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ═══════════════════════════════════════════════════════════════════
# MODERN UI THEME - Dark Cyber
# ═══════════════════════════════════════════════════════════════════
THEME = {
    'bg': "#000000",
    'card': '#1a1f3a',
    'accent': "#effff8",
    'accent2': '#00d4ff',
    'danger': '#ff0055',
    'warning': '#ffaa00',
    'success': '#00ff88',
    'text': '#e8edf3',
    'text_dim': '#8b95a8',
    'border': '#2a3f5f'
}

# ═══════════════════════════════════════════════════════════════════
# RECONNAISSANCE MODULE
# ═══════════════════════════════════════════════════════════════════
class ReconEngine:
    """Advanced reconnaissance and information gathering"""
    
    def __init__(self, session):
        self.session = session
        
    def gather_info(self, domain):
        """Gather comprehensive domain information"""
        print(f"Starting recon for: {domain}")  # Debug
        results = {
            'domain': domain,
            'ip_info': self.get_ip_info(domain),
            'dns_records': self.get_dns_records(domain),
            'ssl_info': self.get_ssl_info(domain),
            'http_headers': self.get_http_headers(domain),
            'technologies': self.detect_technologies(domain),
            'subdomains': self.find_subdomains(domain),
            'robots_txt': self.check_robots(domain),
            'sitemap': self.check_sitemap(domain),
            'security_headers': self.check_security_headers(domain),
            'emails': self.find_emails(domain),
            'social_media': self.find_social_media(domain)
        }
        print(f"Recon complete: {results}")  # Debug
        return results
    
    def get_ip_info(self, domain):
        """Get IP address and location info"""
        try:
            clean_domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
            ip = socket.gethostbyname(clean_domain)
            
            # Get geolocation
            try:
                geo_response = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
                geo_data = geo_response.json() if geo_response.status_code == 200 else {}
            except:
                geo_data = {}
            
            return {
                'ip': ip,
                'country': geo_data.get('country', 'Unknown'),
                'region': geo_data.get('regionName', 'Unknown'),
                'city': geo_data.get('city', 'Unknown'),
                'isp': geo_data.get('isp', 'Unknown'),
                'org': geo_data.get('org', 'Unknown')
            }
        except Exception as e:
            return {'error': str(e), 'ip': 'Unable to resolve'}
    
    def get_dns_records(self, domain):
        """Get DNS records using socket (simplified)"""
        records = {}
        clean_domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
        
        try:
            # A Record
            try:
                ip = socket.gethostbyname(clean_domain)
                records['A'] = [ip]
            except:
                records['A'] = []
            
            # Basic hostname info
            try:
                hostname = socket.gethostbyaddr(records['A'][0])[0] if records['A'] else None
                records['PTR'] = [hostname] if hostname else []
            except:
                records['PTR'] = []
                
        except Exception as e:
            records['error'] = str(e)
        
        return records
    
    def get_ssl_info(self, domain):
        """Get SSL/TLS certificate information"""
        try:
            clean_domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
            context = ssl.create_default_context()
            
            with socket.create_connection((clean_domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=clean_domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    issuer_dict = dict(x[0] for x in cert.get('issuer', []))
                    subject_dict = dict(x[0] for x in cert.get('subject', []))
                    
                    return {
                        'issuer': issuer_dict.get('organizationName', 'Unknown'),
                        'subject': subject_dict.get('commonName', 'Unknown'),
                        'version': cert.get('version', 'Unknown'),
                        'valid_from': cert.get('notBefore', 'Unknown'),
                        'valid_until': cert.get('notAfter', 'Unknown'),
                        'serial_number': cert.get('serialNumber', 'Unknown')
                    }
        except Exception as e:
            return {'error': f'HTTPS not available: {str(e)}'}
    
    def get_http_headers(self, domain):
        """Get HTTP response headers"""
        try:
            url = domain if domain.startswith('http') else f'http://{domain}'
            response = self.session.head(url, timeout=10, verify=False, allow_redirects=True)
            return dict(response.headers)
        except Exception as e:
            return {'error': str(e)}
    
    def detect_technologies(self, domain):
        """Detect web technologies used"""
        technologies = []
        try:
            url = domain if domain.startswith('http') else f'http://{domain}'
            response = self.session.get(url, timeout=10, verify=False)
            
            headers = response.headers
            content = response.text.lower()
            
            # Server detection
            if 'server' in headers:
                technologies.append(f"Server: {headers['server']}")
            
            # Framework detection
            if 'x-powered-by' in headers:
                technologies.append(f"Powered by: {headers['x-powered-by']}")
            
            # CMS detection
            if 'wp-content' in content or 'wordpress' in content:
                technologies.append("CMS: WordPress")
            elif 'joomla' in content:
                technologies.append("CMS: Joomla")
            elif 'drupal' in content:
                technologies.append("CMS: Drupal")
            
            # JavaScript frameworks
            if 'react' in content:
                technologies.append("Frontend: React")
            elif 'vue' in content:
                technologies.append("Frontend: Vue.js")
            elif 'angular' in content:
                technologies.append("Frontend: Angular")
            
            # Analytics
            if 'google-analytics' in content or 'gtag' in content:
                technologies.append("Analytics: Google Analytics")
            
        except Exception as e:
            technologies.append(f"Detection error: {str(e)}")
        
        return technologies if technologies else ['Unable to detect']
    
    def find_subdomains(self, domain):
        """Find subdomains using common names"""
        clean_domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
        common_subs = ['www', 'mail', 'ftp', 'api', 'dev', 'test', 'staging', 
                       'admin', 'blog', 'shop', 'forum', 'support', 'cdn']
        
        found = []
        for sub in common_subs:
            try:
                full_domain = f"{sub}.{clean_domain}"
                ip = socket.gethostbyname(full_domain)
                found.append(f"{full_domain} → {ip}")
            except:
                pass
        
        return found if found else ['No subdomains found']
    
    def check_robots(self, domain):
        """Check robots.txt"""
        try:
            url = domain if domain.startswith('http') else f'http://{domain}'
            response = self.session.get(f"{url}/robots.txt", timeout=5, verify=False)
            if response.status_code == 200:
                lines = response.text.split('\n')[:20]
                return '\n'.join(lines)
            return 'Not found'
        except:
            return 'Not found'
    
    def check_sitemap(self, domain):
        """Check for sitemap"""
        try:
            url = domain if domain.startswith('http') else f'http://{domain}'
            response = self.session.get(f"{url}/sitemap.xml", timeout=5, verify=False)
            return 'Found' if response.status_code == 200 else 'Not found'
        except:
            return 'Not found'
    
    def check_security_headers(self, domain):
        """Check security headers"""
        try:
            url = domain if domain.startswith('http') else f'http://{domain}'
            response = self.session.get(url, timeout=10, verify=False)
            
            headers_to_check = {
                'Strict-Transport-Security': 'HSTS',
                'X-Frame-Options': 'Clickjacking Protection',
                'X-Content-Type-Options': 'MIME Sniffing Protection',
                'Content-Security-Policy': 'CSP',
                'X-XSS-Protection': 'XSS Protection',
                'Referrer-Policy': 'Referrer Policy'
            }
            
            results = {}
            for header, name in headers_to_check.items():
                results[name] = '✓ Present' if header in response.headers else '✗ Missing'
            
            return results
        except:
            return {'error': 'Unable to check'}
    
    def find_emails(self, domain):
        """Find email addresses"""
        try:
            url = domain if domain.startswith('http') else f'http://{domain}'
            response = self.session.get(url, timeout=10, verify=False)
            
            email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            emails = list(set(re.findall(email_pattern, response.text)))[:5]
            
            return emails if emails else ['No emails found']
        except:
            return ['Unable to scan']
    
    def find_social_media(self, domain):
        """Find social media links"""
        try:
            url = domain if domain.startswith('http') else f'http://{domain}'
            response = self.session.get(url, timeout=10, verify=False)
            
            platforms = {
                'Facebook': r'facebook\.com/[\w-]+',
                'Twitter': r'twitter\.com/[\w-]+',
                'LinkedIn': r'linkedin\.com/[\w-/]+',
                'Instagram': r'instagram\.com/[\w-]+',
                'YouTube': r'youtube\.com/[\w-]+'
            }
            
            found = []
            for platform, pattern in platforms.items():
                matches = re.findall(pattern, response.text)
                if matches:
                    found.append(f"{platform}: {matches[0]}")
            
            return found if found else ['No social media links found']
        except:
            return ['Unable to scan']

# ═══════════════════════════════════════════════════════════════════
# NETWORK SCANNER
# ═══════════════════════════════════════════════════════════════════
class NetworkScanner:
    """Advanced network port scanning and service detection"""
    
    def __init__(self):
        self.common_ports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
            445: 'SMB', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
            5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt',
            9200: 'Elasticsearch', 27017: 'MongoDB'
        }
    
    def scan_port(self, host, port, timeout=1):
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def grab_banner(self, host, port, timeout=2):
        """Grab service banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            
            sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            return banner[:200] if banner else None
        except:
            return None
    
    def scan_host(self, host, port_range, callback=None):
        """Scan host for open ports"""
        results = []
        
        # Parse port range
        if '-' in port_range:
            start, end = map(int, port_range.split('-'))
            ports = range(start, min(end + 1, 65536))
        else:
            ports = [int(p) for p in port_range.replace(' ', '').split(',') if p.isdigit()]
        
        print(f"Scanning {len(list(ports))} ports on {host}")  # Debug
        
        for port in ports:
            if self.scan_port(host, port):
                service = self.common_ports.get(port, 'Unknown')
                banner = self.grab_banner(host, port)
                
                results.append({
                    'port': port,
                    'service': service,
                    'banner': banner,
                    'state': 'open'
                })
                
                print(f"Found open port: {port}/{service}")  # Debug
                
                if callback:
                    callback(port, service, banner)
        
        return results

# ═══════════════════════════════════════════════════════════════════
# VULNERABILITY DETECTOR
# ═══════════════════════════════════════════════════════════════════
class VulnerabilityDetector:
    """Advanced vulnerability detection"""
    
    @staticmethod
    def detect_xss(response, payload, original_response):
        score = 0
        findings = []
        
        if payload not in response.text:
            return False, []
        
        if re.search(f'<script[^>]*>{re.escape(payload)}', response.text, re.I):
            score += 10
            findings.append("Reflected in <script> tag")
        
        if re.search(f'(?:on\w+|href|src)=["\']?[^"\']*{re.escape(payload)}', response.text, re.I):
            score += 9
            findings.append("Reflected in event handler")
        
        csp = response.headers.get('Content-Security-Policy', '')
        if not csp or 'unsafe-inline' in csp:
            score += 3
            findings.append("Weak/missing CSP")
        
        return score >= 8, findings
    
    @staticmethod
    def detect_sqli(response, payload, original_response, timing=None):
        score = 0
        findings = []
        
        if timing and timing > 5:
            score += 10
            findings.append(f"Time delay: {timing:.2f}s")
            return True, findings
        
        sql_errors = [
            r"SQL syntax.*?MySQL", r"Warning.*?mysql_", r"PostgreSQL.*?ERROR",
            r"Warning.*?pg_", r"Microsoft SQL", r"OLE DB.*? SQL Server"
        ]
        
        for pattern in sql_errors:
            if re.search(pattern, response.text, re.I):
                score += 10
                findings.append("SQL error detected")
                break
        
        if original_response:
            diff = abs(len(original_response.text) - len(response.text))
            if diff > 100:
                score += 6
                findings.append(f"Content difference: {diff} chars")
        
        return score >= 9, findings
    
    @staticmethod
    def detect_lfi(response, payload):
        findings = []
        score = 0
        
        patterns = [
            (r'root:.*?:0:0:', "Found /etc/passwd"),
            (r'\[extensions\]', "Found win.ini"),
            (r'<\?php', "PHP source exposed")
        ]
        
        for pattern, desc in patterns:
            if re.search(pattern, response.text, re.I):
                score += 10
                findings.append(desc)
        
        return score >= 10, findings
    
    @staticmethod
    def detect_rce(response, payload):
        findings = []
        score = 0
        
        patterns = [
            (r'uid=\d+.*?gid=\d+', "Unix UID/GID"),
            (r'Linux.*?\d+\.\d+', "Linux kernel version"),
            (r'Microsoft Windows', "Windows version")
        ]
        
        for pattern, desc in patterns:
            if re.search(pattern, response.text, re.I):
                score += 10
                findings.append(desc)
                break
        
        return score >= 10, findings

# ═══════════════════════════════════════════════════════════════════
# PAYLOAD GENERATOR
# ═══════════════════════════════════════════════════════════════════
class PayloadGenerator:
    @staticmethod
    def get_xss_payloads():
        return [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "' autofocus onfocus=alert(1) '",
            "<iframe srcdoc='<script>alert(1)</script>'>"
        ]
    
    @staticmethod
    def get_sqli_payloads():
        return [
            "' OR '1'='1",
            "1' AND SLEEP(5)--",
            "1' UNION SELECT NULL,NULL--",
            "1'; DROP TABLE users--"
        ]
    
    @staticmethod
    def get_lfi_payloads():
        return [
            "../../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "php://filter/convert.base64-encode/resource=index.php"
        ]
    
    @staticmethod
    def get_rce_payloads():
        return [
            "; id",
            "| whoami",
            "`uname -a`",
            "$(cat /etc/passwd)"
        ]

# ═══════════════════════════════════════════════════════════════════
# MAIN APPLICATION
# ═══════════════════════════════════════════════════════════════════
class SecuritySuite:
    def __init__(self, root):
        self.root = root
        self.root.title("WEB VULNERABILITY SCANNER")
        self.root.geometry("1700x1000")
        self.root.configure(bg=THEME['bg'])
        
        # State
        self.scanning = Event()
        self.lock = Lock()
        self.vulnerabilities = []
        self.recon_data = {}
        self.network_results = []
        
        # Session
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Engines
        self.recon_engine = ReconEngine(self.session)
        self.network_scanner = NetworkScanner()
        self.vuln_detector = VulnerabilityDetector()
        self.payload_gen = PayloadGenerator()
        
        # Settings
        self.settings = {
            'threads': 5,
            'timeout': 10,
            'follow_redirects': True,
            'verify_ssl': False,
            'auto_export': False,
            'verbose': True
        }
        
        self.setup_ui()
        
        # Show success message
        self.root.after(1000, lambda: self.status_label.config(
            text="● Ready - Enter target and click SCAN ALL",
            fg=THEME['success']
        ))

    def set_initial_focus(self):
        """Set initial focus and select text in target entry"""
        self.target_entry.focus()
        self.target_entry.select_range(0, tk.END)
        
    def setup_ui(self):
        # ═══════════════════════════════════════════════════════════
        # HEADER
        # ═══════════════════════════════════════════════════════════
        header = tk.Frame(self.root, bg=THEME['bg'], height=80)
        header.pack(fill='x', padx=30, pady=(15, 5))
        
        tk.Label(header, text="🛡️ WEB APPLICATION VULNERABILITY SCANNER", 
                font=('Arial', 26, 'bold'), 
                bg=THEME['bg'], fg=THEME['accent']).pack(side='left')
        
        tk.Label(header, text="", 
                font=('Arial', 10), 
                bg=THEME['bg'], fg=THEME['text_dim']).pack(side='left', padx=20)
        
        # ═══════════════════════════════════════════════════════════
        # MAIN TARGET INPUT
        # ═══════════════════════════════════════════════════════════
        target_frame = tk.Frame(self.root, bg=THEME['card'])
        target_frame.pack(fill='x', padx=30, pady=15)
        
        tk.Label(target_frame, text="TARGET:", font=('Arial', 11, 'bold'),
                bg=THEME['card'], fg=THEME['text']).pack(side='left', padx=(20, 10), pady=15)
        
        self.target_entry = tk.Entry(target_frame, font=('Arial', 12),
                                     bg=THEME['bg'], fg=THEME['text'],
                                     insertbackground=THEME['accent'], width=70)
        self.target_entry.pack(side='left', padx=10, pady=15, fill='x', expand=True)
        self.target_entry.insert(0, "testphp.vulnweb.com")
        # Set focus and select after UI is fully rendered
        self.root.after(500, self.set_initial_focus)
        
        self.scan_all_btn = tk.Button(target_frame, text="🚀 SCAN ALL", 
                                      command=self.scan_all,
                                      font=('Arial', 11, 'bold'), 
                                      bg=THEME['accent'], fg='#000',
                                      relief='flat', cursor='hand2',
                                      padx=25, pady=10)
        self.scan_all_btn.pack(side='right', padx=20, pady=10)
        
        # ═══════════════════════════════════════════════════════════
        # TABBED INTERFACE
        # ═══════════════════════════════════════════════════════════
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=30, pady=(0, 15))
        
        # Style notebook
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TNotebook', background=THEME['bg'], borderwidth=0)
        style.configure('TNotebook.Tab', background=THEME['card'], 
                       foreground=THEME['text'], padding=[20, 10],
                       font=('Arial', 10, 'bold'))
        style.map('TNotebook.Tab', background=[('selected', THEME['accent'])],
                 foreground=[('selected', '#000')])
        
        # Create tabs
        self.setup_recon_tab()
        self.setup_vuln_tab()
        self.setup_network_tab()
        self.setup_settings_tab()
        
        # ═══════════════════════════════════════════════════════════
        # STATUS BAR
        # ═══════════════════════════════════════════════════════════
        status_bar = tk.Frame(self.root, bg=THEME['card'], height=40)
        status_bar.pack(fill='x', side='bottom')
        
        self.status_label = tk.Label(status_bar, text="● Initializing...", 
                                     font=('Arial', 10), 
                                     bg=THEME['card'], fg=THEME['warning'])
        self.status_label.pack(side='left', padx=20, pady=10)
        
        tk.Label(status_bar, text="⚠️ Authorized Testing Only", 
                font=('Arial', 9), 
                bg=THEME['card'], fg=THEME['warning']).pack(side='right', padx=20)
    
    # ═══════════════════════════════════════════════════════════════
    # RECONNAISSANCE TAB
    # ═══════════════════════════════════════════════════════════════
    def setup_recon_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="📡 RECONNAISSANCE")
        
        # Control buttons
        btn_frame = tk.Frame(tab, bg=THEME['bg'])
        btn_frame.pack(fill='x', padx=20, pady=15)
        
        tk.Button(btn_frame, text="🔍 Start Recon", 
                 command=self.start_recon,
                 font=('Arial', 10, 'bold'), 
                 bg=THEME['accent2'], fg='#000',
                 relief='flat', cursor='hand2',
                 padx=20, pady=8).pack(side='left', padx=5)
        
        tk.Button(btn_frame, text="💾 Export Report", 
                 command=self.export_recon,
                 font=('Arial', 10), 
                 bg=THEME['card'], fg=THEME['text'],
                 relief='flat', cursor='hand2',
                 padx=20, pady=8).pack(side='left', padx=5)
        
        # Results area
        results_frame = tk.Frame(tab, bg=THEME['card'])
        results_frame.pack(fill='both', expand=True, padx=20, pady=(0, 20))
        
        self.recon_text = scrolledtext.ScrolledText(
            results_frame, font=('Consolas', 9),
            bg=THEME['bg'], fg=THEME['text'],
            insertbackground=THEME['accent'],
            wrap=tk.WORD, relief='flat'
        )
        self.recon_text.pack(fill='both', expand=True, padx=15, pady=15)
        
        # Configure tags
        self.recon_text.tag_config('header', foreground=THEME['accent'], font=('Consolas', 11, 'bold'))
        self.recon_text.tag_config('success', foreground=THEME['success'], font=('Consolas', 9, 'bold'))
        self.recon_text.tag_config('warning', foreground=THEME['warning'])
        self.recon_text.tag_config('info', foreground=THEME['text_dim'])
        self.recon_text.tag_config('danger', foreground=THEME['danger'])
    
    def start_recon(self):
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return
        
        print(f"Starting recon for: {target}")  # Debug
        self.recon_text.delete('1.0', tk.END)
        self.status_label.config(text="● Gathering intelligence...", fg=THEME['warning'])
        
        Thread(target=self.run_recon, args=(target,), daemon=True).start()
    
    def run_recon(self, target):
        try:
            print("Recon thread started")  # Debug
            self.log_recon("═" * 80, 'header')
            self.log_recon(f"🎯 TARGET: {target}", 'header')
            self.log_recon(f"📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 'info')
            self.log_recon("═" * 80 + "\n", 'header')
            
            # Gather all information
            self.log_recon("🔍 Gathering information...\n", 'success')
            
            data = self.recon_engine.gather_info(target)
            self.recon_data = data
            
            print(f"Got recon data: {data.keys()}")  # Debug
            
            # Display results
            self.display_recon_results(data)
            
            self.status_label.config(text="● Recon complete", fg=THEME['success'])
        except Exception as e:
            print(f"Recon error: {e}")  # Debug
            import traceback
            traceback.print_exc()
            self.log_recon(f"\n❌ Error: {e}", 'danger')
            self.status_label.config(text="● Recon failed", fg=THEME['danger'])
    
    def display_recon_results(self, data):
        # IP Information
        self.log_recon("\n🌐 IP INFORMATION", 'header')
        self.log_recon("─" * 50, 'info')
        if 'error' not in data['ip_info'] or data['ip_info'].get('ip'):
            for key, value in data['ip_info'].items():
                self.log_recon(f"  {key.upper()}: {value}", 'info')
        else:
            self.log_recon(f"  Error: {data['ip_info'].get('error', 'Unknown')}", 'danger')
        
        # DNS Records
        self.log_recon("\n🔎 DNS RECORDS", 'header')
        self.log_recon("─" * 50, 'info')
        if 'error' not in data['dns_records']:
            for record_type, records in data['dns_records'].items():
                if records:
                    self.log_recon(f"  {record_type}:", 'success')
                    for record in records:
                        self.log_recon(f"    • {record}", 'info')
        
        # SSL Information
        self.log_recon("\n🔒 SSL/TLS CERTIFICATE", 'header')
        self.log_recon("─" * 50, 'info')
        if 'error' not in data['ssl_info']:
            for key, value in data['ssl_info'].items():
                self.log_recon(f"  {key.replace('_', ' ').title()}: {value}", 'info')
        else:
            self.log_recon(f"  {data['ssl_info']['error']}", 'warning')
        
        # Technologies
        self.log_recon("\n⚙️ TECHNOLOGIES DETECTED", 'header')
        self.log_recon("─" * 50, 'info')
        for tech in data['technologies']:
            self.log_recon(f"  • {tech}", 'success')
        
        # Security Headers
        self.log_recon("\n🛡️ SECURITY HEADERS", 'header')
        self.log_recon("─" * 50, 'info')
        if 'error' not in data['security_headers']:
            for header, status in data['security_headers'].items():
                color = 'success' if '✓' in status else 'danger'
                self.log_recon(f"  {header}: {status}", color)
        
        # Subdomains
        self.log_recon("\n🌍 SUBDOMAINS FOUND", 'header')
        self.log_recon("─" * 50, 'info')
        for subdomain in data['subdomains'][:10]:
            self.log_recon(f"  • {subdomain}", 'info')
        
        # Emails
        self.log_recon("\n📧 EMAIL ADDRESSES", 'header')
        self.log_recon("─" * 50, 'info')
        for email in data['emails'][:10]:
            self.log_recon(f"  • {email}", 'info')
        
        # Social Media
        self.log_recon("\n📱 SOCIAL MEDIA", 'header')
        self.log_recon("─" * 50, 'info')
        for social in data['social_media']:
            self.log_recon(f"  • {social}", 'info')
        
        # Robots.txt
        self.log_recon("\n🤖 ROBOTS.TXT", 'header')
        self.log_recon("─" * 50, 'info')
        robots = data['robots_txt']
        if robots != 'Not found':
            for line in robots.split('\n')[:15]:
                self.log_recon(f"  {line}", 'info')
        else:
            self.log_recon(f"  {robots}", 'warning')
        
        self.log_recon("\n" + "═" * 80, 'header')
        self.log_recon("✓ RECONNAISSANCE COMPLETE", 'success')
        self.log_recon("═" * 80, 'header')
    
    def log_recon(self, message, tag='info'):
        self.root.after(0, self._log_recon_ui, message, tag)
    
    def _log_recon_ui(self, message, tag):
        self.recon_text.insert(tk.END, message + '\n', tag)
        self.recon_text.see(tk.END)
    
    # ═══════════════════════════════════════════════════════════════
    # VULNERABILITY SCANNER TAB
    # ═══════════════════════════════════════════════════════════════
    def setup_vuln_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🔓 VULNERABILITY SCANNER")
        
        # Stats cards
        stats_frame = tk.Frame(tab, bg=THEME['bg'])
        stats_frame.pack(fill='x', padx=20, pady=15)
        
        self.vuln_stats = {}
        for label, color in [('VULNERABILITIES', THEME['danger']), 
                             ('SCANNED', THEME['accent2']), 
                             ('TIME', THEME['warning'])]:
            card = tk.Frame(stats_frame, bg=THEME['card'])
            card.pack(side='left', fill='both', expand=True, padx=5)
            
            tk.Label(card, text=label, font=('Arial', 9),
                    bg=THEME['card'], fg=THEME['text_dim']).pack(pady=(10, 5))
            
            val = tk.Label(card, text='0', font=('Arial', 24, 'bold'),
                          bg=THEME['card'], fg=color)
            val.pack(pady=(0, 10))
            self.vuln_stats[label.lower()] = val
        
        # Scan modules
        modules_frame = tk.Frame(tab, bg=THEME['card'])
        modules_frame.pack(fill='x', padx=20, pady=10)
        
        tk.Label(modules_frame, text="SCAN MODULES:", font=('Arial', 10, 'bold'),
                bg=THEME['card'], fg=THEME['text']).pack(anchor='w', padx=15, pady=(10, 5))
        
        mod_check_frame = tk.Frame(modules_frame, bg=THEME['card'])
        mod_check_frame.pack(fill='x', padx=15, pady=(0, 10))
        
        self.vuln_modules = {}
        for module in ['XSS', 'SQLi', 'LFI', 'RCE']:
            var = tk.BooleanVar(value=True)
            cb = tk.Checkbutton(mod_check_frame, text=module, variable=var,
                               font=('Arial', 10), bg=THEME['card'], fg=THEME['text'],
                               selectcolor=THEME['bg'], activebackground=THEME['card'])
            cb.pack(side='left', padx=15)
            self.vuln_modules[module] = var
        
        # Control buttons
        btn_frame = tk.Frame(tab, bg=THEME['bg'])
        btn_frame.pack(fill='x', padx=20, pady=10)
        
        tk.Button(btn_frame, text="🚀 Start Scan", 
                 command=self.start_vuln_scan,
                 font=('Arial', 10, 'bold'), 
                 bg=THEME['accent'], fg='#000',
                 relief='flat', cursor='hand2',
                 padx=20, pady=8).pack(side='left', padx=5)
        
        tk.Button(btn_frame, text="⏹ Stop", 
                 command=self.stop_scan,
                 font=('Arial', 10), 
                 bg=THEME['danger'], fg='#fff',
                 relief='flat', cursor='hand2',
                 padx=20, pady=8).pack(side='left', padx=5)
        
        tk.Button(btn_frame, text="💾 Export", 
                 command=self.export_vulns,
                 font=('Arial', 10), 
                 bg=THEME['accent2'], fg='#000',
                 relief='flat', cursor='hand2',
                 padx=20, pady=8).pack(side='left', padx=5)
        
        # Results
        results_frame = tk.Frame(tab, bg=THEME['card'])
        results_frame.pack(fill='both', expand=True, padx=20, pady=(0, 20))
        
        self.vuln_text = scrolledtext.ScrolledText(
            results_frame, font=('Consolas', 9),
            bg=THEME['bg'], fg=THEME['text'],
            insertbackground=THEME['accent'],
            wrap=tk.WORD, relief='flat'
        )
        self.vuln_text.pack(fill='both', expand=True, padx=15, pady=15)
        
        self.vuln_text.tag_config('critical', foreground=THEME['danger'], font=('Consolas', 9, 'bold'))
        self.vuln_text.tag_config('header', foreground=THEME['accent'], font=('Consolas', 11, 'bold'))
        self.vuln_text.tag_config('info', foreground=THEME['text_dim'])
        self.vuln_text.tag_config('success', foreground=THEME['success'])
    
    def start_vuln_scan(self):
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return
        
        if not target.startswith('http'):
            target = 'http://' + target
        
        self.vuln_text.delete('1.0', tk.END)
        self.vulnerabilities = []
        self.vuln_start_time = time.time()
        self.vuln_stats['vulnerabilities'].config(text='0')
        self.vuln_stats['scanned'].config(text='0')
        self.vuln_stats['time'].config(text='00:00')
        
        self.scanning.set()
        self.update_vuln_stats()
        
        Thread(target=self.run_vuln_scan, args=(target,), daemon=True).start()
    
    def run_vuln_scan(self, target):
        try:
            self.log_vuln("═" * 80, 'header')
            self.log_vuln(f"🎯 TARGET: {target}", 'header')
            self.log_vuln("═" * 80 + "\n", 'header')
            
            self.status_label.config(text="● Scanning for vulnerabilities...", fg=THEME['warning'])
            
            # Discover endpoints
            endpoints = self.discover_endpoints(target)
            self.total_endpoints = len(endpoints)
            self.scanned_endpoints = 0
            
            self.log_vuln(f"✓ Discovered {len(endpoints)} endpoints\n", 'success')
            
            # Test each endpoint
            with ThreadPoolExecutor(max_workers=self.settings['threads']) as executor:
                futures = [executor.submit(self.test_vuln_endpoint, ep) for ep in endpoints]
                
                for future in as_completed(futures):
                    if not self.scanning.is_set():
                        break
                    try:
                        future.result()
                        self.scanned_endpoints += 1
                    except Exception as e:
                        print(f"Endpoint test error: {e}")
            
            self.scanning.clear()
            self.log_vuln("\n" + "═" * 80, 'header')
            self.log_vuln("✓ SCAN COMPLETE", 'success')
            self.log_vuln(f"🚨 Total vulnerabilities: {len(self.vulnerabilities)}", 'critical')
            self.log_vuln("═" * 80, 'header')
            
            self.status_label.config(text="● Scan complete", fg=THEME['success'])
        except Exception as e:
            print(f"Vuln scan error: {e}")
            import traceback
            traceback.print_exc()
            self.log_vuln(f"\n❌ Error: {e}", 'critical')
    
    def discover_endpoints(self, url):
        endpoints = set()
        try:
            r = self.session.get(url, timeout=10, verify=False)
            soup = BeautifulSoup(r.text, 'html.parser')
            
            for form in soup.find_all('form'):
                action = form.get('action', '')
                full_url = urljoin(url, action) if action else url
                endpoints.add(full_url)
            
            for link in soup.find_all('a', href=True):
                href = link['href']
                full_url = urljoin(url, href)
                parsed = urlparse(full_url)
                
                if parsed.netloc == urlparse(url).netloc and parsed.query:
                    endpoints.add(full_url)
            
            endpoints.add(url)
        except:
            endpoints.add(url)
        
        return list(endpoints)[:20]
    
    def test_vuln_endpoint(self, url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            params = {'id': ['1'], 'q': ['test']}
        
        for param_name in params:
            if not self.scanning.is_set():
                break
            
            if self.vuln_modules['XSS'].get():
                self.test_xss_vuln(url, param_name)
            
            if self.vuln_modules['SQLi'].get():
                self.test_sqli_vuln(url, param_name)
            
            if self.vuln_modules['LFI'].get():
                self.test_lfi_vuln(url, param_name)
            
            if self.vuln_modules['RCE'].get():
                self.test_rce_vuln(url, param_name)
    
    def test_xss_vuln(self, url, param):
        try:
            original = self.session.get(url, timeout=10, verify=False)
            
            for payload in self.payload_gen.get_xss_payloads():
                if not self.scanning.is_set():
                    break
                
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                params[param] = [payload]
                
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                response = self.session.get(test_url, params=params, timeout=10, verify=False)
                
                is_vuln, findings = self.vuln_detector.detect_xss(response, payload, original)
                
                if is_vuln:
                    self.report_vuln('XSS', url, param, payload, findings)
                    break
        except:
            pass
    
    def test_sqli_vuln(self, url, param):
        try:
            original = self.session.get(url, timeout=10, verify=False)
            
            for payload in self.payload_gen.get_sqli_payloads():
                if not self.scanning.is_set():
                    break
                
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                params[param] = [payload]
                
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                
                start = time.time()
                try:
                    response = self.session.get(test_url, params=params, timeout=15, verify=False)
                    elapsed = time.time() - start
                except:
                    continue
                
                is_vuln, findings = self.vuln_detector.detect_sqli(response, payload, original, elapsed)
                
                if is_vuln:
                    self.report_vuln('SQLi', url, param, payload, findings)
                    break
        except:
            pass
    
    def test_lfi_vuln(self, url, param):
        try:
            for payload in self.payload_gen.get_lfi_payloads():
                if not self.scanning.is_set():
                    break
                
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                params[param] = [payload]
                
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                response = self.session.get(test_url, params=params, timeout=10, verify=False)
                
                is_vuln, findings = self.vuln_detector.detect_lfi(response, payload)
                
                if is_vuln:
                    self.report_vuln('LFI', url, param, payload, findings)
                    break
        except:
            pass
    
    def test_rce_vuln(self, url, param):
        try:
            for payload in self.payload_gen.get_rce_payloads():
                if not self.scanning.is_set():
                    break
                
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                params[param] = [payload]
                
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                response = self.session.get(test_url, params=params, timeout=10, verify=False)
                
                is_vuln, findings = self.vuln_detector.detect_rce(response, payload)
                
                if is_vuln:
                    self.report_vuln('RCE', url, param, payload, findings)
                    break
        except:
            pass
    
    def report_vuln(self, vuln_type, url, param, payload, findings):
        with self.lock:
            vuln = {
                'type': vuln_type,
                'url': url,
                'parameter': param,
                'payload': payload,
                'findings': findings,
                'timestamp': datetime.now().isoformat()
            }
            self.vulnerabilities.append(vuln)
            
            self.log_vuln(f"\n🚨 [{vuln_type}] VULNERABILITY FOUND!", 'critical')
            self.log_vuln(f"   URL: {url}", 'info')
            self.log_vuln(f"   Parameter: {param}", 'info')
            self.log_vuln(f"   Payload: {payload[:100]}", 'info')
            for finding in findings:
                self.log_vuln(f"   • {finding}", 'info')
    
    def log_vuln(self, message, tag='info'):
        self.root.after(0, self._log_vuln_ui, message, tag)
    
    def _log_vuln_ui(self, message, tag):
        self.vuln_text.insert(tk.END, message + '\n', tag)
        self.vuln_text.see(tk.END)
    
    def update_vuln_stats(self):
        if self.scanning.is_set():
            self.vuln_stats['vulnerabilities'].config(text=str(len(self.vulnerabilities)))
            self.vuln_stats['scanned'].config(text=str(getattr(self, 'scanned_endpoints', 0)))
            
            elapsed = int(time.time() - self.vuln_start_time)
            mins, secs = divmod(elapsed, 60)
            self.vuln_stats['time'].config(text=f"{mins:02d}:{secs:02d}")
            
            self.root.after(500, self.update_vuln_stats)
    
    # ═══════════════════════════════════════════════════════════════
    # NETWORK SCANNER TAB
    # ═══════════════════════════════════════════════════════════════
    def setup_network_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🌐 NETWORK SCANNER")
        
        # Target config
        config_frame = tk.Frame(tab, bg=THEME['card'])
        config_frame.pack(fill='x', padx=20, pady=15)
        
        tk.Label(config_frame, text="HOST:", font=('Arial', 10, 'bold'),
                bg=THEME['card'], fg=THEME['text']).grid(row=0, column=0, padx=15, pady=10, sticky='w')
        
        self.net_host = tk.Entry(config_frame, font=('Arial', 11),
                                bg=THEME['bg'], fg=THEME['text'],
                                insertbackground=THEME['accent'], width=40)
        self.net_host.grid(row=0, column=1, padx=10, pady=10, sticky='ew')
        #self.net_host.insert(0, "")
        
        tk.Label(config_frame, text="PORTS:", font=('Arial', 10, 'bold'),
                bg=THEME['card'], fg=THEME['text']).grid(row=1, column=0, padx=15, pady=10, sticky='w')
        
        self.net_ports = tk.Entry(config_frame, font=('Arial', 11),
                                 bg=THEME['bg'], fg=THEME['text'],
                                 insertbackground=THEME['accent'], width=40)
        self.net_ports.grid(row=1, column=1, padx=10, pady=10, sticky='ew')
        self.net_ports.insert(0, "1-100")
        
        config_frame.columnconfigure(1, weight=1)
        
        # Port presets
        presets_frame = tk.Frame(tab, bg=THEME['bg'])
        presets_frame.pack(fill='x', padx=20, pady=10)
        
        tk.Label(presets_frame, text="PRESETS:", font=('Arial', 9),
                bg=THEME['bg'], fg=THEME['text_dim']).pack(side='left', padx=5)
        
        for text, ports in [('Quick (1-100)', '1-100'), 
                           ('Web Ports', '80,443,8080,8443'),
                           ('Common', '21,22,23,25,80,443,3306'),
                           ('Extended', '1-1000')]:
            tk.Button(presets_frame, text=text,
                     command=lambda p=ports: (self.net_ports.delete(0, 'end'), 
                                            self.net_ports.insert(0, p)),
                     font=('Arial', 9), bg=THEME['card'], fg=THEME['text'],
                     relief='flat', cursor='hand2', padx=15, pady=5).pack(side='left', padx=5)
        
        # Control buttons
        btn_frame = tk.Frame(tab, bg=THEME['bg'])
        btn_frame.pack(fill='x', padx=20, pady=15)
        
        tk.Button(btn_frame, text="🚀 Start Scan", 
                 command=self.start_network_scan,
                 font=('Arial', 10, 'bold'), 
                 bg=THEME['accent'], fg='#000',
                 relief='flat', cursor='hand2',
                 padx=20, pady=8).pack(side='left', padx=5)
        
        tk.Button(btn_frame, text="⏹ Stop", 
                 command=self.stop_scan,
                 font=('Arial', 10), 
                 bg=THEME['danger'], fg='#fff',
                 relief='flat', cursor='hand2',
                 padx=20, pady=8).pack(side='left', padx=5)
        
        # Results
        results_frame = tk.Frame(tab, bg=THEME['card'])
        results_frame.pack(fill='both', expand=True, padx=20, pady=(0, 20))
        
        self.net_text = scrolledtext.ScrolledText(
            results_frame, font=('Consolas', 9),
            bg=THEME['bg'], fg=THEME['text'],
            insertbackground=THEME['accent'],
            wrap=tk.WORD, relief='flat'
        )
        self.net_text.pack(fill='both', expand=True, padx=15, pady=15)
        
        self.net_text.tag_config('open', foreground=THEME['success'], font=('Consolas', 9, 'bold'))
        self.net_text.tag_config('header', foreground=THEME['accent'], font=('Consolas', 11, 'bold'))
        self.net_text.tag_config('info', foreground=THEME['text_dim'])
        self.net_text.tag_config('banner', foreground=THEME['warning'])
    
    def start_network_scan(self):
        host = self.net_host.get().strip()
        ports = self.net_ports.get().strip()
        
        if not host or not ports:
            messagebox.showerror("Error", "Please enter host and ports")
            return
        
        self.net_text.delete('1.0', tk.END)
        self.scanning.set()
        self.status_label.config(text="● Scanning network...", fg=THEME['warning'])
        
        Thread(target=self.run_network_scan, args=(host, ports), daemon=True).start()
    
    def run_network_scan(self, host, port_range):
        try:
            self.log_net("═" * 80, 'header')
            self.log_net(f"🎯 TARGET: {host}", 'header')
            self.log_net(f"🔌 PORTS: {port_range}", 'header')
            self.log_net("═" * 80 + "\n", 'header')
            
            # Resolve host
            try:
                ip = socket.gethostbyname(host)
                self.log_net(f"✓ Resolved: {host} → {ip}\n", 'info')
            except:
                self.log_net(f"✗ Failed to resolve host\n", 'info')
                self.scanning.clear()
                return
            
            # Scan ports
            def callback(port, service, banner):
                self.log_net(f"[OPEN] {port}/tcp - {service}", 'open')
                if banner:
                    self.log_net(f"       Banner: {banner[:100]}", 'banner')
            
            results = self.network_scanner.scan_host(ip, port_range, callback)
            self.network_results = results
            
            self.log_net(f"\n" + "═" * 80, 'header')
            self.log_net(f"✓ SCAN COMPLETE", 'open')
            self.log_net(f"📊 Found {len(results)} open ports", 'info')
            self.log_net("═" * 80, 'header')
            
            self.scanning.clear()
            self.status_label.config(text="● Network scan complete", fg=THEME['success'])
        except Exception as e:
            print(f"Network scan error: {e}")
            import traceback
            traceback.print_exc()
            self.log_net(f"\n❌ Error: {e}", 'info')
    
    def log_net(self, message, tag='info'):
        self.root.after(0, self._log_net_ui, message, tag)
    
    def _log_net_ui(self, message, tag):
        self.net_text.insert(tk.END, message + '\n', tag)
        self.net_text.see(tk.END)
    
    # ═══════════════════════════════════════════════════════════════
    # SETTINGS TAB
    # ═══════════════════════════════════════════════════════════════
    def setup_settings_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="⚙️ SETTINGS")
        
        settings_container = tk.Frame(tab, bg=THEME['bg'])
        settings_container.pack(fill='both', expand=True, padx=40, pady=30)
        
        # Scan Settings
        scan_frame = tk.LabelFrame(settings_container, text="  SCAN SETTINGS  ",
                                  font=('Arial', 11, 'bold'),
                                  bg=THEME['card'], fg=THEME['accent'],
                                  relief='flat', padx=20, pady=20)
        scan_frame.pack(fill='x', pady=10)
        
        tk.Label(scan_frame, text="Concurrent Threads:", font=('Arial', 10),
                bg=THEME['card'], fg=THEME['text']).grid(row=0, column=0, sticky='w', pady=10)
        
        self.threads_var = tk.IntVar(value=self.settings['threads'])
        threads_spinbox = tk.Spinbox(scan_frame, from_=1, to=20, textvariable=self.threads_var,
                                    font=('Arial', 10), width=10,
                                    bg=THEME['bg'], fg=THEME['text'])
        threads_spinbox.grid(row=0, column=1, padx=20, pady=10, sticky='w')
        
        tk.Label(scan_frame, text="Request Timeout (seconds):", font=('Arial', 10),
                bg=THEME['card'], fg=THEME['text']).grid(row=1, column=0, sticky='w', pady=10)
        
        self.timeout_var = tk.IntVar(value=self.settings['timeout'])
        timeout_spinbox = tk.Spinbox(scan_frame, from_=5, to=60, textvariable=self.timeout_var,
                                    font=('Arial', 10), width=10,
                                    bg=THEME['bg'], fg=THEME['text'])
        timeout_spinbox.grid(row=1, column=1, padx=20, pady=10, sticky='w')
        
        self.follow_redirects_var = tk.BooleanVar(value=self.settings['follow_redirects'])
        tk.Checkbutton(scan_frame, text="Follow Redirects", variable=self.follow_redirects_var,
                      font=('Arial', 10), bg=THEME['card'], fg=THEME['text'],
                      selectcolor=THEME['bg']).grid(row=2, column=0, sticky='w', pady=5)
        
        self.verbose_var = tk.BooleanVar(value=self.settings['verbose'])
        tk.Checkbutton(scan_frame, text="Verbose Output", variable=self.verbose_var,
                      font=('Arial', 10), bg=THEME['card'], fg=THEME['text'],
                      selectcolor=THEME['bg']).grid(row=3, column=0, sticky='w', pady=5)
        
        # About Section
        about_frame = tk.LabelFrame(settings_container, text="  ABOUT  ",
                                   font=('Arial', 11, 'bold'),
                                   bg=THEME['card'], fg=THEME['accent'],
                                   relief='flat', padx=20, pady=20)
        about_frame.pack(fill='x', pady=10)
        
        about_text = """WEB APPLICATION VULNERABILITY SCANNER

Features:
• Advanced Reconnaissance & OSINT
• Vulnerability Detection (XSS, SQLi, LFI, RCE)
• Network Port Scanning & Banner Grabbing
• Technology Detection
• Security Header Analysis
• DNS Enumeration
• Subdomain Discovery

⚠️ WARNING: Use only on authorized targets
⚖️ Unauthorized access is illegal

Created for security professionals and ethical hackers."""
        
        tk.Label(about_frame, text=about_text, font=('Arial', 9),
                bg=THEME['card'], fg=THEME['text'], justify='left').pack(anchor='w')
        
        # Save button
        btn_frame = tk.Frame(settings_container, bg=THEME['bg'])
        btn_frame.pack(pady=20)
        
        tk.Button(btn_frame, text="💾 Save Settings", 
                 command=self.save_settings,
                 font=('Arial', 11, 'bold'), 
                 bg=THEME['accent'], fg='#000',
                 relief='flat', cursor='hand2',
                 padx=30, pady=10).pack()
    
    def save_settings(self):
        self.settings['threads'] = self.threads_var.get()
        self.settings['timeout'] = self.timeout_var.get()
        self.settings['follow_redirects'] = self.follow_redirects_var.get()
        self.settings['verbose'] = self.verbose_var.get()
        
        messagebox.showinfo("Success", "Settings saved successfully!")
    
    # ═══════════════════════════════════════════════════════════════
    # SCAN ALL FUNCTIONALITY
    # ═══════════════════════════════════════════════════════════════
    def scan_all(self):
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return
        
        if not messagebox.askyesno("Confirm", 
                                   f"Run complete security assessment on:\n{target}\n\n" +
                                   "This will perform:\n" +
                                   "• Reconnaissance\n" +
                                   "• Vulnerability Scanning\n" +
                                   "• Network Scanning\n\n" +
                                   "Ensure you have permission!"):
            return
        
        Thread(target=self.run_complete_scan, args=(target,), daemon=True).start()
    
    def run_complete_scan(self, target):
        self.status_label.config(text="● Running complete assessment...", fg=THEME['warning'])
        
        # 1. Reconnaissance
        self.notebook.select(0)
        time.sleep(0.5)
        self.run_recon(target)
        time.sleep(2)
        
        # 2. Vulnerability Scan
        self.notebook.select(1)
        if not target.startswith('http'):
            target = 'http://' + target
        time.sleep(0.5)
        self.run_vuln_scan(target)
        
        while self.scanning.is_set():
            time.sleep(1)
        
        # 3. Network Scan
        try:
            domain = target.replace('http://', '').replace('https://', '').split('/')[0]
            self.net_host.delete(0, tk.END)
            self.net_host.insert(0, domain)
            self.net_ports.delete(0, tk.END)
            self.net_ports.insert(0, "1-100")
            
            self.notebook.select(2)
            time.sleep(0.5)
            self.run_network_scan(domain, "1-100")
        except Exception as e:
            print(f"Network scan error in scan_all: {e}")
        
        messagebox.showinfo("Complete", "Security assessment finished!\n\nCheck all tabs for results.")
        self.status_label.config(text="● Assessment complete", fg=THEME['success'])
    
    # ═══════════════════════════════════════════════════════════════
    # EXPORT FUNCTIONS
    # ═══════════════════════════════════════════════════════════════
    def export_recon(self):
        if not self.recon_data:
            messagebox.showinfo("Info", "No recon data to export")
            return
        
        filepath = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("Text", "*.txt")]
        )
        
        if filepath:
            try:
                if filepath.endswith('.json'):
                    with open(filepath, 'w') as f:
                        json.dump(self.recon_data, f, indent=2)
                else:
                    with open(filepath, 'w') as f:
                        f.write(self.recon_text.get('1.0', tk.END))
                
                messagebox.showinfo("Success", f"Recon data exported to:\n{filepath}")
            except Exception as e:
                messagebox.showerror("Error", f"Export failed: {e}")
    
    def export_vulns(self):
        if not self.vulnerabilities:
            messagebox.showinfo("Info", "No vulnerabilities to export")
            return
        
        filepath = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML Report", "*.html"), ("JSON", "*.json")]
        )
        
        if filepath:
            try:
                if filepath.endswith('.html'):
                    self.export_html_report(filepath)
                else:
                    report = {
                        'target': self.target_entry.get(),
                        'timestamp': datetime.now().isoformat(),
                        'vulnerabilities': self.vulnerabilities
                    }
                    with open(filepath, 'w') as f:
                        json.dump(report, f, indent=2)
                
                messagebox.showinfo("Success", f"Report exported to:\n{filepath}")
            except Exception as e:
                messagebox.showerror("Error", f"Export failed: {e}")
    
    def export_html_report(self, filepath):
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Security Assessment Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Arial; background: #0a0e27; color: #e8edf3; padding: 40px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ background: linear-gradient(135deg, #1a1f3a 0%, #2a3f5f 100%); 
                   padding: 40px; border-radius: 15px; margin-bottom: 30px; }}
        h1 {{ color: #00ff88; font-size: 36px; margin-bottom: 10px; }}
        .stats {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin: 30px 0; }}
        .stat-card {{ background: #1a1f3a; padding: 25px; border-radius: 10px; }}
        .stat-value {{ color: #00ff88; font-size: 32px; font-weight: bold; }}
        .section {{ background: #1a1f3a; padding: 30px; border-radius: 10px; margin-bottom: 20px; }}
        .vuln {{ background: #0a0e27; padding: 20px; margin: 15px 0; border-radius: 8px; 
                border-left: 4px solid #ff0055; }}
        .vuln-type {{ color: #ff0055; font-weight: bold; font-size: 18px; }}
        code {{ background: #0a0e27; padding: 2px 8px; border-radius: 3px; color: #00d4ff; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 Security Assessment Report</h1>
            <p><strong>Target:</strong> {self.target_entry.get()}</p>
            <p><strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div>Total Vulnerabilities</div>
                <div class="stat-value">{len(self.vulnerabilities)}</div>
            </div>
            <div class="stat-card">
                <div>Critical Issues</div>
                <div class="stat-value">{sum(1 for v in self.vulnerabilities if v['type'] in ['SQLi', 'RCE'])}</div>
            </div>
            <div class="stat-card">
                <div>Endpoints Tested</div>
                <div class="stat-value">{getattr(self, 'total_endpoints', 0)}</div>
            </div>
        </div>
        
        <div class="section">
            <h2 style="color: #00ff88; margin-bottom: 20px;">Vulnerabilities Found</h2>
"""
        
        if not self.vulnerabilities:
            html += '<p style="color: #8b95a8;">No vulnerabilities detected.</p>'
        else:
            for vuln in self.vulnerabilities:
                html += f"""
            <div class="vuln">
                <div class="vuln-type">[{vuln['type']}] Vulnerability</div>
                <p><strong>URL:</strong> {vuln['url']}</p>
                <p><strong>Parameter:</strong> <code>{vuln['parameter']}</code></p>
                <p><strong>Payload:</strong> <code>{vuln['payload']}</code></p>
                <div style="margin-top: 10px; color: #8b95a8;">
                    <strong>Evidence:</strong>
"""
                for finding in vuln['findings']:
                    html += f'<div>• {finding}</div>'
                
                html += """
                </div>
            </div>
"""
        
        html += """
        </div>
    </div>
</body>
</html>"""
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html)
    
    def stop_scan(self):
        if self.scanning.is_set():
            self.scanning.clear()
            self.status_label.config(text="● Scan stopped", fg=THEME['danger'])

# ═══════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════
def main():
    root = tk.Tk()
    
    disclaimer = """
═══════════════════════════════════════════════════
    WEB APPLICATION VULNERABILITY SCANNER
    LEGAL DISCLAIMER
═══════════════════════════════════════════════════

⚠️  WARNING: AUTHORIZED USE ONLY

This tool is for LEGITIMATE SECURITY TESTING.

You MUST have explicit permission to test any target.
Unauthorized access is ILLEGAL.

By clicking "I AGREE", you confirm:
  ✓ You have legal authorization
  ✓ You understand applicable laws
  ✓ You will use this tool responsibly
  ✓ Authors bear NO responsibility for misuse

═══════════════════════════════════════════════════
"""
    
    response = messagebox.askokcancel("Legal Disclaimer", disclaimer)
    
    if not response:
        root.destroy()
        return
    
    try:
        print("Starting application...")
        app = SecuritySuite(root)
        print("Application initialized successfully")
        root.mainloop()
    except Exception as e:
        print(f"Application error: {e}")
        import traceback
        traceback.print_exc()
        messagebox.showerror("Error", f"Failed to start:\n{e}")
        root.destroy()

if __name__ == "__main__":
    main()
