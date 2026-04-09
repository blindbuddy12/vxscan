# VXScan+ 🔍

VXScan+ is an advanced Python-based **web vulnerability scanner** built for learning, research, and portfolio demonstration.

It performs automated scanning of web applications to identify common security vulnerabilities with improved accuracy and reduced false positives.

---

## 🚀 Features

### 🔐 Vulnerability Detection
- SQL Injection (Error-based, Boolean-based, Time-based)
- Cross-Site Scripting (XSS)
- Local File Inclusion (LFI)
- Open Redirects
- Sensitive File Exposure
- Directory Bruteforce

### 🧠 Advanced Capabilities
- Heuristic AI-based anomaly detection (response analysis)
- Context-aware payload injection
- Cookie-based authenticated scanning
- Multi-threaded crawling & testing
- Reduced false positives using baseline comparison

### 📊 Reporting
- JSON report (for automation)
- Markdown report (for readability)
- HTML report (clean UI dashboard)

---

## 🖥️ GUI Dashboard

VXScan+ includes a simple GUI for easier usage.

### Run GUI:
```bash```
python gui.py

## Usage
```bash```
python vxscan.py --url http://example.com --max-pages 20 --depth 2

## Example Report

![Report 1](screenshots/report1.png)  
![Report 2](screenshots/report2.png)

⚠️ Disclaimer

This tool is for educational and authorized testing only.

Do NOT scan systems without permission.

🧑‍💻 Author

Developed as a cybersecurity learning project to demonstrate:

Web security fundamentals
Vulnerability detection techniques
Secure coding practices

⭐ Future Improvements

More vulnerability modules (SSRF, IDOR, Command Injection)
Machine Learning-based detection
Web dashboard (Flask)
Burp Suite-like interface

