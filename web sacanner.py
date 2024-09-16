import os
import requests
from urllib.parse import urljoin
import html

# Payloads for XSS and Directory Traversal
xss_payloads = ["<script>alert('XSS')</script>", "<img src='x' onerror='alert(1)'>"]
dir_traversal_payloads = ["../etc/passwd", "../../windows/win.ini"]

# Function to log output to a file at a specific location
def log_to_file(message, filename="vulnerability_report.txt", directory=None):
    if directory:
        # Ensure the directory exists
        if not os.path.exists(directory):
            os.makedirs(directory)
        # Create the full path
        filepath = os.path.join(directory, filename)
    else:
        filepath = filename
    
    with open(filepath, "a") as f:
        f.write(message + "\n")

# Function to scan for XSS vulnerabilities
def scan_xss(url, log_dir=None):
    results = []
    for payload in xss_payloads:
        target_url = f"{url}?q={payload}"
        try:
            response = requests.get(target_url, timeout=10)
            # Analyze the response for XSS vulnerabilities
            if is_xss_vulnerable(response.text, payload):
                result = f"[!] XSS vulnerability detected: {target_url}"
                results.append(result)
                log_to_file(f"XSS payload '{payload}' triggered in response: {response.text}", directory=log_dir)
        except requests.exceptions.RequestException as e:
            error_message = f"Error scanning {target_url}: {e}"
            log_to_file(error_message, directory=log_dir)
    return results

# Function to scan for Directory Traversal vulnerabilities
def scan_dir_traversal(url, log_dir=None):
    results = []
    for payload in dir_traversal_payloads:
        target_url = f"{url}?file={payload}"
        try:
            response = requests.get(target_url, timeout=10)
            # Analyze the response for Directory Traversal vulnerabilities
            if is_dir_traversal_vulnerable(response.text, payload):
                result = f"[!] Directory Traversal vulnerability detected: {target_url}"
                results.append(result)
                log_to_file(f"Directory Traversal payload '{payload}' triggered in response: {response.text}", directory=log_dir)
        except requests.exceptions.RequestException as e:
            error_message = f"Error scanning {target_url}: {e}"
            log_to_file(error_message, directory=log_dir)
    return results

# Function to analyze response for XSS vulnerabilities
def is_xss_vulnerable(response_text, payload):
    # Check if the payload is reflected in the response
    if payload in response_text:
        return True
    # Check if the response contains suspicious HTML tags
    if any(tag in response_text for tag in ["<script>", "<img", "<iframe"]):
        return True
    return False

# Function to analyze response for Directory Traversal vulnerabilities
def is_dir_traversal_vulnerable(response_text, payload):
    # Check if the payload is reflected in the response
    if payload in response_text:
        return True
    # Check if the response contains suspicious file paths
    if any(path in response_text for path in ["/etc/passwd", "/windows/win.ini"]):
        return True
    return False

# Main function to run the scanner
def run_scanner(base_url, log_dir=None):
    log_to_file(f"Scanning {base_url} for vulnerabilities...", directory=log_dir)
    base_url = base_url if base_url.endswith('/') else base_url + '/'
    endpoints = ["search", "download", "view"]

    results = []
    for endpoint in endpoints:
        full_url = urljoin(base_url, endpoint)
        print(f"Scanning {full_url}...")
        xss_results = scan_xss(full_url, log_dir)
        dir_traversal_results = scan_dir_traversal(full_url, log_dir)
        results.extend(xss_results)
        results.extend(dir_traversal_results)

    # Generate a report
    if results:
        report = "Vulnerabilities Found:\n"
        for result in results:
            report += f"- {result}\n"
    else:
        report = "No vulnerabilities found."

    log_to_file(report, directory=log_dir)
    print(report)

# Example usage
if __name__ == "__main__":
    target_website = "http://www.vulnweb.com/"
    log_directory = "D:\CYBER SECURITY"  # Specify your desired directory here
    run_scanner(target_website, log_dir=log_directory)