# VXScan+

VXScan+ is an advanced Python-based **web vulnerability scanner**.  
It detects:
- SQL Injection (Error-based, Time-based)
- Cross-Site Scripting (XSS)
- Local File Inclusion (LFI)
- Open Redirects
- Sensitive File Exposures

## Features
- Context-aware payloads → fewer false positives
- Cookie-based authenticated scans
- Multi-format reporting: **JSON, Markdown, HTML**
- Modular design (easy to extend with new payloads)

## Usage
```bash
python vxscan.py --url http://example.com/
