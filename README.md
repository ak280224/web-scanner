# Web Application Vulnerability Scanner  
## A GUI-Based VAPT Security Assessment Tool

The **Web Application Vulnerability Scanner** is a comprehensive security assessment tool developed in **Python** with a graphical user interface using **Tkinter**. The application is designed to perform **Vulnerability Assessment and Penetration Testing (VAPT)** by combining reconnaissance, web vulnerability scanning, and network port scanning into a single integrated platform.

This project demonstrates practical implementation of real-world security testing techniques used by security analysts and penetration testers.

---

## Project Overview

Modern web applications are frequently exposed to security risks due to misconfigurations, insecure coding practices, and insufficient testing. This tool aims to automate and simplify the initial phases of a security assessment by identifying potential weaknesses in web applications and network services.

The scanner follows a structured security testing approach:
1. Reconnaissance and information gathering  
2. Web application vulnerability assessment  
3. Network and service exposure analysis  
4. Report generation and export  

---

## Objectives

- To design and implement a complete VAPT workflow in a single application  
- To automate reconnaissance and attack surface discovery  
- To identify common and high-impact web vulnerabilities  
- To provide a user-friendly interface for security testing  
- To generate clear and structured security assessment reports  

---

## Core Features

### 1. Reconnaissance and Information Gathering

The reconnaissance module collects publicly accessible information related to the target, which is critical for understanding the overall attack surface.

Capabilities include:
- IP address resolution and basic geolocation
- DNS record enumeration (A and PTR records)
- SSL/TLS certificate analysis
- HTTP response and security header inspection
- Technology and content management system detection
- Subdomain discovery using common subdomain patterns
- robots.txt and sitemap.xml detection
- Email address extraction
- Social media link identification

---

### 2. Vulnerability Assessment and Penetration Testing (VAPT)

The vulnerability scanning module actively tests web application endpoints and parameters using controlled payload injection and response analysis.

Supported vulnerability classes:
- Cross-Site Scripting (XSS)
- SQL Injection (SQLi), including error-based and time-based techniques
- Local File Inclusion (LFI)
- Remote Code Execution (RCE)

Detection methodology:
- Payload reflection and response validation
- Content-length comparison between baseline and injected responses
- Timing-based analysis for blind SQL injection
- Regular expression–based evidence matching
- Security header and Content Security Policy (CSP) evaluation

The scanner supports multi-parameter testing and uses multi-threading to improve scan efficiency.

---

### 3. Network and Port Scanning

The network scanning module identifies exposed services at the infrastructure level.

Features include:
- TCP port scanning using socket-based connections
- Custom and predefined port ranges
- Common service identification
- Basic banner grabbing for service fingerprinting

---

### 4. Reporting and Exporting

The tool provides export functionality for documentation and reporting purposes.

Supported formats:
- Reconnaissance results: JSON and text files
- Vulnerability assessment reports: HTML and JSON

Reports include vulnerability details, affected parameters, payloads used, and supporting evidence.

---

## User Interface

The application provides a clean and structured graphical interface with tab-based navigation:
- Reconnaissance
- Vulnerability Scanner
- Network Scanner
- Settings

The interface displays real-time scan progress, vulnerability statistics, and scan duration. Scan execution can be started or stopped at any time.

---

## Technology Stack

- Programming Language: Python 3  
- Graphical User Interface: Tkinter  
- HTTP Communication: requests  
- HTML Parsing: BeautifulSoup  
- Networking: socket, ssl  
- Concurrency: ThreadPoolExecutor  
- Reporting: JSON and HTML  
