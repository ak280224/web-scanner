import os
import requests
from urllib.parse import urljoin, quote
import html
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from threading import Thread
import time
from itertools import cycle

# Payloads for XSS, Directory Traversal, SQL Injection, and Command Injection
xss_payloads = ["<script>alert('XSS')</script>", "<img src='x' onerror='alert(1)'>"]
dir_traversal_payloads = ["../etc/passwd", "../../windows/win.ini"]
sql_injection_payloads = ["' OR '1'='1", "'; DROP TABLE users; --"]
command_injection_payloads = ["; ls", "| ls", "&& ls"]

# Function to log output to a file at a specific location
def log_to_file(message, filename="vulnerability_report.txt", directory=None):
    if directory:
        if not os.path.exists(directory):
            os.makedirs(directory)
        filepath = os.path.join(directory, filename)
    else:
        filepath = filename
    
    with open(filepath, "a") as f:
        f.write(message + "\n")

# Function to scan for XSS vulnerabilities
def scan_xss(url, log_dir=None):
    results = []
    for payload in xss_payloads:
        encoded_payload = quote(payload)
        target_url = f"{url}?q={encoded_payload}"
        try:
            response = requests.get(target_url, timeout=10)
            if is_xss_vulnerable(response.text, payload):
                result = f"[!] XSS vulnerability detected: {target_url}"
                results.append(result)
                log_to_file(f"XSS payload '{payload}' triggered in response: {response.text}", directory=log_dir)
        except requests.exceptions.RequestException as e:
            log_to_file(f"Error scanning {target_url}: {e}", directory=log_dir)
    return results

# Function to scan for Directory Traversal vulnerabilities
def scan_dir_traversal(url, log_dir=None):
    results = []
    for payload in dir_traversal_payloads:
        encoded_payload = quote(payload)
        target_url = f"{url}?file={encoded_payload}"
        try:
            response = requests.get(target_url, timeout=10)
            if is_dir_traversal_vulnerable(response.text, payload):
                result = f"[!] Directory Traversal vulnerability detected: {target_url}"
                results.append(result)
                log_to_file(f"Directory Traversal payload '{payload}' triggered in response: {response.text}", directory=log_dir)
        except requests.exceptions.RequestException as e:
            log_to_file(f"Error scanning {target_url}: {e}", directory=log_dir)
    return results

# Function to scan for SQL Injection vulnerabilities
def scan_sql_injection(url, log_dir=None):
    results = []
    for payload in sql_injection_payloads:
        encoded_payload = quote(payload)
        target_url = f"{url}?id={encoded_payload}"
        try:
            response = requests.get(target_url, timeout=10)
            if is_sql_injection_vulnerable(response.text, payload):
                result = f"[!] SQL Injection vulnerability detected: {target_url}"
                results.append(result)
                log_to_file(f"SQL Injection payload '{payload}' triggered in response: {response.text}", directory=log_dir)
        except requests.exceptions.RequestException as e:
            log_to_file(f"Error scanning {target_url}: {e}", directory=log_dir)
    return results

# Function to scan for Command Injection vulnerabilities
def scan_command_injection(url, log_dir=None):
    results = []
    for payload in command_injection_payloads:
        encoded_payload = quote(payload)
        target_url = f"{url}?cmd={encoded_payload}"
        try:
            response = requests.get(target_url, timeout=10)
            if is_command_injection_vulnerable(response.text, payload):
                result = f"[!] Command Injection vulnerability detected: {target_url}"
                results.append(result)
                log_to_file(f"Command Injection payload '{payload}' triggered in response: {response.text}", directory=log_dir)
        except requests.exceptions.RequestException as e:
            log_to_file(f"Error scanning {target_url}: {e}", directory=log_dir)
    return results

# Function to analyze response for XSS vulnerabilities
def is_xss_vulnerable(response_text, payload):
    response_text = html.unescape(response_text)
    return payload in response_text or any(tag in response_text for tag in ["<script>", "<img", "<iframe"])

# Function to analyze response for Directory Traversal vulnerabilities
def is_dir_traversal_vulnerable(response_text, payload):
    response_text = html.unescape(response_text)
    return payload in response_text or any(path in response_text for path in ["/etc/passwd", "/windows/win.ini"])

# Function to analyze response for SQL Injection vulnerabilities
def is_sql_injection_vulnerable(response_text, payload):
    response_text = html.unescape(response_text)
    # Check for common SQL error messages or unexpected output
    error_indicators = ["SQL syntax", "MySQL", "error in your SQL syntax", "Warning: mysql"]
    return any(indicator in response_text for indicator in error_indicators)

# Function to analyze response for Command Injection vulnerabilities
def is_command_injection_vulnerable(response_text, payload):
    response_text = html.unescape(response_text)
    # Check for command output or indicators of command execution
    command_indicators = ["root", "bin", "usr", "etc"]
    return any(indicator in response_text for indicator in command_indicators)

# Function to handle spinning animation during scanning
def spinning_animation(label):
    spinner = cycle(['|', '/', '-', '\\'])
    while True:
        label.config(text=next(spinner))
        time.sleep(0.1)

# Main function to run the scanner
def run_scanner(base_url, log_dir=None):
    results_box.insert(tk.END, f"Scanning {base_url} for vulnerabilities...\n")
    log_to_file(f"Scanning {base_url} for vulnerabilities...", directory=log_dir)

    base_url = base_url if base_url.endswith('/') else base_url + '/'
    endpoints = ["search", "download", "view"]

    results = []
    spinner_label = tk.Label(root, text="|", font=("Helvetica", 14), bg=bg_color, fg=fg_color)
    spinner_label.grid(row=5, column=1)

    spinner_thread = Thread(target=spinning_animation, args=(spinner_label,))
    spinner_thread.daemon = True
    spinner_thread.start()

    try:
        for endpoint in endpoints:
            full_url = urljoin(base_url, endpoint)
            results_box.insert(tk.END, f"Scanning {full_url}...\n")
            xss_results = scan_xss(full_url, log_dir)
            dir_traversal_results = scan_dir_traversal(full_url, log_dir)
            sql_injection_results = scan_sql_injection(full_url, log_dir)
            command_injection_results = scan_command_injection(full_url, log_dir)

            results.extend(xss_results)
            results.extend(dir_traversal_results)
            results.extend(sql_injection_results)
            results.extend(command_injection_results)

        # Generate a report
        if results:
            report = "Vulnerabilities Found:\n"
            for result in results:
                report += f"- {result}\n"
                results_box.insert(tk.END, f"{result}\n")
        else:
            report = "No vulnerabilities found."
            results_box.insert(tk.END, "No vulnerabilities found.\n")

        log_to_file(report, directory=log_dir)
        results_box.insert(tk.END, report + "\n")
    finally:
        spinner_label.destroy()

# GUI Setup with Tkinter
def browse_directory():
    dir_name = filedialog.askdirectory()
    log_directory_entry.delete(0, tk.END)
    log_directory_entry.insert(0, dir_name)

def start_scan():
    target_url = url_entry.get()
    log_dir = log_directory_entry.get()

    if not target_url:
        messagebox.showerror("Error", "Please enter a target URL")
        return

    # Run the scanner in a separate thread
    Thread(target=run_scanner, args=(target_url, log_dir)).start()

# Aesthetic Enhancements for the GUI
root = tk.Tk()
root.title("Web Vulnerability Scanner")

# Set theme colors
bg_color = "#282c34"
fg_color = "#abb2bf"
button_color = "#61afef"
entry_bg_color = "#3e4451"
text_bg_color = "#21252b"

# Set window size and background color
root.geometry("700x600")
root.configure(bg=bg_color)

# Custom fonts
title_font = ("Helvetica", 16, "bold")
label_font = ("Helvetica", 12)
entry_font = ("Helvetica", 11)
button_font = ("Helvetica", 11, "bold")

# Title Label
title_label = tk.Label(root, text="Web Vulnerability Scanner", font=title_font, bg=bg_color, fg="#e5c07b")
title_label.grid(row=0, column=0, columnspan=3, padx=20, pady=20)

# Target URL Input
tk.Label(root, text="Target URL:", font=label_font, bg=bg_color, fg=fg_color).grid(row=1, column=0, padx=20, pady=10, sticky="w")
url_entry = tk.Entry(root, width=50, font=entry_font, bg=entry_bg_color, fg=fg_color, relief="flat")
url_entry.grid(row=1, column=1, padx=10, pady=10)

# Log Directory Input
tk.Label(root, text="Log Directory:", font=label_font, bg=bg_color, fg=fg_color).grid(row=2, column=0, padx=20, pady=10, sticky="w")
log_directory_entry = tk.Entry(root, width=50, font=entry_font, bg=entry_bg_color, fg=fg_color, relief="flat")
log_directory_entry.grid(row=2, column=1, padx=10, pady=10)
browse_button = tk.Button(root, text="Browse", font=button_font, bg=button_color, fg="white", command=browse_directory)
browse_button.grid(row=2, column=2, padx=10, pady=10)

# Results Box (Scrolled Text)
tk.Label(root, text="Results:", font=label_font, bg=bg_color, fg=fg_color).grid(row=3, column=0, padx=20, pady=10, sticky="w")
results_box = scrolledtext.ScrolledText(root, width=80, height=20, font=entry_font, bg=text_bg_color, fg=fg_color, relief="flat")
results_box.grid(row=4, column=0, columnspan=3, padx=20, pady=10)

# Start Scan Button
start_button = tk.Button(root, text="Start Scan", font=button_font, bg=button_color, fg="white", command=start_scan)
start_button.grid(row=5, column=0, columnspan=3, pady=20)

# Set padding for widgets
for widget in root.winfo_children():
    widget.grid_configure(padx=10, pady=5)

root.mainloop()
