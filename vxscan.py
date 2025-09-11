#!/usr/bin/env python3
"""
VXScan+ — Improved Lightweight Web Vulnerability Scanner (educational)
=====================================================================

What’s new vs. original
-----------------------
• Context-aware payloads (HTML/attribute) for XSS
• SQLi: error/boolean/time-based with smarter baselines
• LFI, Open Redirect, Sensitive files, Dir brute-force
• Security header & cookie flag checks
• Auth support via --cookie (manual session)
• External payload extension via --payloads payloads.json
• Multi-threaded crawling & scanning
• JSON, Markdown, and HTML reports with severity + evidence

⚠️ Legal/Ethical Use: Only scan systems you own or have explicit, written permission to test.
This tool is for learning/defensive validation; false positives/negatives are possible — always validate manually.
"""
from __future__ import annotations

import argparse
import concurrent.futures as futures
import html
import json
import os
import queue
import random
import re
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlencode, urlunparse, parse_qs

# Optional: colored CLI if installed
try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    C_OK, C_BAD, C_INFO = Fore.GREEN, Fore.RED, Fore.CYAN
except Exception:  # pragma: no cover
    class _C:
        def __getattr__(self, _):
            return ""
    Fore = Style = _C()
    C_OK, C_BAD, C_INFO = "", "", ""

requests.packages.urllib3.disable_warnings()  # quiet self-signed warnings for labs

# -----------------------------
# Payloads (can be extended via --payloads)
# -----------------------------
SQL_ERROR_REGEXES = [
    re.compile(r"SQL syntax.*MySQL", re.I),
    re.compile(r"Warning: mysql_", re.I),
    re.compile(r"PostgreSQL.*ERROR", re.I),
    re.compile(r"You have an error in your SQL", re.I),
    re.compile(r"SQLSTATE\[HY000\]", re.I),
    re.compile(r"SQLite.Exception|System.Data.SQLite", re.I),
    re.compile(r"Microsoft OLE DB Provider|ODBC SQL Server Driver", re.I),
]

XSS_PAYLOADS: List[str] = [
    "<script>alert('xss')</script>",                 # HTML context
    "\"><img src=x onerror=alert(1)>",             # Attribute break-out
    "\"><svg/onload=alert(1)>",                   # SVG handler
    "' ; alert(1) ; //",                            # JS context
]

# SQLi split by technique
SQLI_PAYLOADS = {
    "error": ["'", '"', "')-- ", '" )-- '],
    "boolean_true": ["1' AND '1'='1"],
    "boolean_false": ["1' AND '1'='2"],
    "time": ["1' OR SLEEP(4)-- ", '" OR SLEEP(4)-- '],
}

LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
]

SENSITIVE_FILES = [
    "robots.txt", ".env", ".git/HEAD", ".git/config", "sitemap.xml", "crossdomain.xml",
    "server-status", ".htaccess", "phpinfo.php"
]

# Probe for common files and extensions (new enhancement)
COMMON_DIRS = [
    "admin/", "admin/login", "administrator/", "backup/", "backups/", "old/", "test/", "dev/",
    ".git/", "config/", "login", "dashboard", "server-status",
]

# file basenames and extensions to probe for (will be reported if accessible)
COMMON_FILE_BASENAMES = ["index", "config", "backup", "db", "admin", "test", "dev", "setup", "install"]
COMMON_FILE_EXTS = [".php", ".html", ".htm", ".bak", ".inc"]

OPEN_REDIRECT_PARAMS = ["next", "url", "target", "dest", "destination", "redirect", "redir", "return", "go", "r"]

DEFAULT_HEADERS = {
    "User-Agent": f"VXScan/2.1 (+edu) {random.randint(1000,9999)}",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

# -----------------------------
# Data models
# -----------------------------
@dataclass
class Finding:
    type: str
    url: str
    detail: str
    evidence: Optional[str] = None
    severity: str = "Info"  # Info, Low, Medium, High, Critical

@dataclass
class ScanResult:
    target: str
    started: str
    finished: Optional[str] = None
    pages_crawled: int = 0
    findings: List[Finding] = field(default_factory=list)
    headers_by_url: Dict[str, Dict[str, str]] = field(default_factory=dict)
    cookies_by_url: Dict[str, List[Dict[str, str]]] = field(default_factory=dict)

    def add(self, f: Finding):
        self.findings.append(f)

# -----------------------------
# Core Scanner
# -----------------------------
class VXScan:
    def __init__(self, base_url: str, max_pages: int = 60, depth: int = 2, timeout: int = 10, threads: int = 8, cookie: Optional[str] = None, payloads_file: Optional[str] = None):
        self.base_url = self.normalize_url(base_url)
        self.base_origin = self.origin(self.base_url)
        self.max_pages = max_pages
        self.depth = depth
        self.timeout = timeout
        self.threads = threads
        self.session = requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)
        if cookie:
            self.session.headers.update({"Cookie": cookie})
        self.visited: Set[str] = set()
        self.lock = threading.Lock()
        self.result = ScanResult(target=self.base_url, started=datetime.utcnow().isoformat() + "Z")
        # allow external payloads extension
        if payloads_file and os.path.exists(payloads_file):
            try:
                with open(payloads_file, "r", encoding="utf-8") as f:
                    extra = json.load(f)
                XSS_PAYLOADS.extend(extra.get("xss", []))
                for k, v in extra.get("sqli", {}).items():
                    SQLI_PAYLOADS.setdefault(k, []).extend(v)
                LFI_PAYLOADS.extend(extra.get("lfi", []))
            except Exception:
                pass

    # ---------- URL utils ----------
    @staticmethod
    def normalize_url(u: str) -> str:
        if not u.startswith("http"):
            u = "http://" + u
        parts = urlparse(u)
        if not parts.path:
            parts = parts._replace(path="/")
        return urlunparse(parts)

    @staticmethod
    def origin(u: str) -> str:
        p = urlparse(u)
        return f"{p.scheme}://{p.netloc}"

    def same_origin(self, u: str) -> bool:
        return self.origin(u) == self.base_origin

    # ---------- HTTP ----------
    def get(self, url: str, *, allow_redirects: bool = True, params: dict | None = None):
        try:
            return self.session.get(url, params=params, timeout=self.timeout, verify=False, allow_redirects=allow_redirects)
        except requests.RequestException:
            return None

    def post(self, url: str, data: dict, *, allow_redirects: bool = True):
        try:
            return self.session.post(url, data=data, timeout=self.timeout, verify=False, allow_redirects=allow_redirects)
        except requests.RequestException:
            return None

    # ---------- Crawl ----------
    def crawl(self):
        q: queue.Queue[Tuple[str, int]] = queue.Queue()
        q.put((self.base_url, 0))
        self.visited.add(self.base_url)

        while not q.empty() and len(self.visited) < self.max_pages:
            url, d = q.get()
            r = self.get(url)
            if not r:
                continue
            with self.lock:
                self.result.pages_crawled += 1
                self.result.headers_by_url[url] = {k: v for k, v in r.headers.items()}
                self.result.cookies_by_url[url] = [
                    {"name": c.name, "value": c.value, "domain": c.domain, "path": c.path, "secure": str(c.secure)}
                    for c in r.cookies
                ]
            # enqueue links
            soup = BeautifulSoup(r.text, "html.parser")
            for a in soup.find_all("a", href=True):
                href = urljoin(url, a["href"]).split("#")[0]
                if self.same_origin(href) and href not in self.visited:
                    if d + 1 <= self.depth and len(self.visited) < self.max_pages:
                        self.visited.add(href)
                        q.put((href, d + 1))

    # ---------- Checks ----------
    def check_headers_and_cookies(self):
        for url, headers in list(self.result.headers_by_url.items()):
            def has(h):
                return any(k.lower() == h.lower() for k in headers.keys())

            if not has("Content-Security-Policy"):
                self.result.add(Finding("Missing Header", url, "Content-Security-Policy not present", severity="Medium"))
            if url.startswith("https://") and not has("Strict-Transport-Security"):
                self.result.add(Finding("Missing Header", url, "Strict-Transport-Security (HSTS) not present", severity="Low"))
            if not has("X-Frame-Options") and "content-security-policy" not in {k.lower(): v for k, v in headers.items()}:
                self.result.add(Finding("Missing Header", url, "X-Frame-Options not present (clickjacking)", severity="Low"))
            if not has("X-Content-Type-Options"):
                self.result.add(Finding("Missing Header", url, "X-Content-Type-Options not present", severity="Low"))
            if not has("Referrer-Policy"):
                self.result.add(Finding("Missing Header", url, "Referrer-Policy not present", severity="Info"))

            set_cookie = ", ".join([v for k, v in headers.items() if k.lower() == "set-cookie"]) or ""
            if set_cookie:
                lc = set_cookie.lower()
                if "httponly" not in lc:
                    self.result.add(Finding("Cookie", url, "Set-Cookie missing HttpOnly", evidence=set_cookie, severity="Low"))
                if url.startswith("https://") and "secure" not in lc:
                    self.result.add(Finding("Cookie", url, "Set-Cookie missing Secure on HTTPS", evidence=set_cookie, severity="Low"))
                if "samesite" not in lc:
                    self.result.add(Finding("Cookie", url, "Set-Cookie missing SameSite", evidence=set_cookie, severity="Info"))

    # --- XSS ---
    def test_forms_xss(self):
        def analyze_reflection(resp_text: str, payload: str) -> Tuple[bool, str, str]:
            # Determine context of reflection: html/attr/script
            if payload in resp_text:
                # crude context hint
                if f'="{payload}' in resp_text or f"='{payload}" in resp_text:
                    return True, "Attribute", "Reflected inside attribute value"
                if "<script" in resp_text and payload in resp_text:
                    return True, "Script", "Reflected inside script block"
                return True, "HTML", "Reflected in HTML body"
            return False, "", ""

        def test_on_page(url: str, html_text: str):
            soup = BeautifulSoup(html_text, "html.parser")
            forms = soup.find_all("form")
            for form in forms:
                action = form.get("action") or url
                action_url = urljoin(url, action)
                method = (form.get("method") or "get").lower()
                inputs = form.find_all(["input", "textarea"])
                names = [i.get("name") for i in inputs if i.get("name")]
                if not names:
                    continue
                # Baseline for diffing responses
                base_resp = self.get(action_url) if method == "get" else self.post(action_url, {})
                base_len = len(base_resp.text) if base_resp else 0
                for payload in XSS_PAYLOADS:
                    data = {n: payload for n in names}
                    r = self.get(action_url, params=data) if method == "get" else self.post(action_url, data)
                    if not r:
                        continue
                    reflected, ctx, why = analyze_reflection(r.text, payload)
                    # Heuristics to reduce FPs: require reflection AND significant length change or attribute/script context
                    if reflected:
                        delta = abs(len(r.text) - base_len)
                        sev = "High" if ctx in ("HTML", "Script") else "Medium"
                        if delta > 30 or ctx != "HTML":
                            self.result.add(Finding(
                                "Reflected XSS",
                                action_url,
                                f"Payload reflected via form params {names} in {ctx} context — {why}",
                                evidence=payload,
                                severity=sev,
                            ))
                            break

        with futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            futs = []
            for url in list(self.visited):
                r = self.get(url)
                if r:
                    futs.append(ex.submit(test_on_page, url, r.text))
            for _ in futures.as_completed(futs):
                pass

    # --- SQLi ---
    def test_sqli(self):
        def try_inject(url: str):
            parts = urlparse(url)
            qs = parse_qs(parts.query)
            if not qs:
                return
            base_q = {kk: vv[0] for kk, vv in qs.items()}
            # Baseline response to compare against boolean tests
            base_resp = self.get(url)
            base_len = len(base_resp.text) if base_resp else 0
            for k in list(qs.keys()):
                val = qs[k][0]
                # Error-based
                for p in SQLI_PAYLOADS.get("error", []):
                    inj = dict(base_q)
                    inj[k] = val + p
                    target = urlunparse(parts._replace(query=urlencode(inj)))
                    r = self.get(target)
                    if r and any(rx.search(r.text) for rx in SQL_ERROR_REGEXES):
                        self.result.add(Finding("SQL Injection (error-based)", target, f"Parameter '{k}' produced DB error", severity="High"))
                        return
                # Boolean-based
                bt = SQLI_PAYLOADS.get("boolean_true", [])
                bf = SQLI_PAYLOADS.get("boolean_false", [])
                if bt and bf:
                    inj_true = dict(base_q); inj_true[k] = bt[0]
                    inj_false = dict(base_q); inj_false[k] = bf[0]
                    rt = self.get(urlunparse(parts._replace(query=urlencode(inj_true))))
                    rf = self.get(urlunparse(parts._replace(query=urlencode(inj_false))))
                    if rt and rf and abs(len(rt.text) - len(rf.text)) > max(40, int(0.2 * base_len)):
                        self.result.add(Finding("SQL Injection (boolean)", urlunparse(parts._replace(query=urlencode(inj_true))), f"Parameter '{k}' boolean diff detected", severity="High"))
                        return
                # Time-based
                for p in SQLI_PAYLOADS.get("time", []):
                    inj = dict(base_q)
                    inj[k] = val + p
                    target = urlunparse(parts._replace(query=urlencode(inj)))
                    started = time.time()
                    r = self.get(target)
                    elapsed = time.time() - started
                    if r is not None and elapsed > max(3.5, self.timeout * 0.6):
                        self.result.add(Finding("SQL Injection (time-based)", target, f"Parameter '{k}' response delayed {elapsed:.1f}s", severity="High"))
                        return

        with futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            list(ex.map(try_inject, list(self.visited)))

    # --- LFI ---
    def test_lfi(self):
        def try_lfi(url: str):
            parts = urlparse(url)
            qs = parse_qs(parts.query)
            if not qs:
                return
            base_q = {kk: vv[0] for kk, vv in qs.items()}
            for k in list(qs.keys()):
                for p in LFI_PAYLOADS:
                    inj = dict(base_q)
                    inj[k] = p
                    target = urlunparse(parts._replace(query=urlencode(inj)))
                    r = self.get(target)
                    if r and ("root:x:0:" in r.text or "[fonts]" in r.text or "[extensions]" in r.text):
                        self.result.add(Finding("Local File Inclusion", target, f"Parameter '{k}' appears file-include vulnerable", severity="High"))
                        return

        with futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            list(ex.map(try_lfi, list(self.visited)))

    # --- Open Redirect ---
    def test_open_redirect(self):
        def try_redirect(url: str):
            parts = urlparse(url)
            qs = parse_qs(parts.query)
            candidates = [p for p in OPEN_REDIRECT_PARAMS if p in qs]
            if not candidates:
                return
            for k in candidates:
                evil = "https://example.org/evil"
                inj = {kk: vv[0] for kk, vv in qs.items()}
                inj[k] = evil
                target = urlunparse(parts._replace(query=urlencode(inj)))
                r = self.get(target, allow_redirects=False)
                if r is not None and (r.is_redirect or r.status_code in (301, 302, 303, 307, 308)):
                    loc = r.headers.get("Location", "")
                    if evil in loc:
                        self.result.add(Finding("Open Redirect", target, f"Parameter '{k}' allows external redirect", evidence=loc, severity="Medium"))
                        return

        with futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            list(ex.map(try_redirect, list(self.visited)))

    # --- Sensitive Files ---
    def check_sensitive_files(self):
        # 1) Check explicit sensitive paths (legacy behavior)
        for path in SENSITIVE_FILES:
            url = urljoin(self.base_origin + "/", path)
            r = self.get(url)
            if r and r.status_code == 200 and r.text.strip():
                sev = "Medium" if path != "robots.txt" else "Info"
                snippet = r.text[:200].replace("\n", " ")
", " ")
                self.result.add(Finding("Sensitive File", url, f"Accessible {path}", evidence=snippet, severity=sev))

        # 2) Probe for common file basenames with sensitive extensions (new enhancement)
        for base in COMMON_FILE_BASENAMES:
            for ext in COMMON_FILE_EXTS:
                probe_path = f"{base}{ext}"
                url = urljoin(self.base_origin + "/", probe_path)
                r = self.get(url, allow_redirects=False)
                if r and r.status_code == 200 and r.text and len(r.text) > 20:
                    # classify severity: php files often more sensitive
                    sev = "High" if ext in (".php", ".inc") else "Medium"
                    snippet = r.text[:300].replace("
", " ")
                    self.result.add(Finding("Exposed File", url, f"Accessible file {probe_path}", evidence=snippet, severity=sev))

    # --- Dir brute force ---
    def dir_bruteforce(self):
        def probe(path: str):
            url = urljoin(self.base_origin + "/", path)
            r = self.get(url, allow_redirects=False)
            if r is None:
                return
            if r.status_code in (200, 401, 403, 500) or (300 <= r.status_code < 400):
                self.result.add(Finding("Interesting Path", url, f"Status {r.status_code}", severity="Info"))

        with futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            list(ex.map(probe, COMMON_DIRS))

    # ---------- Reporting ----------
    def save_reports(self, outdir: str = "reports") -> Tuple[str, str, str]:
        os.makedirs(outdir, exist_ok=True)
        host = urlparse(self.base_url).netloc.replace(":", "_")
        stamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        json_path = os.path.join(outdir, f"vxscan_{host}_{stamp}.json")
        md_path = os.path.join(outdir, f"vxscan_{host}_{stamp}.md")
        html_path = os.path.join(outdir, f"vxscan_{host}_{stamp}.html")

        self.result.finished = datetime.utcnow().isoformat() + "Z"

        # JSON
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump({
                "target": self.result.target,
                "started": self.result.started,
                "finished": self.result.finished,
                "pages_crawled": self.result.pages_crawled,
                "findings": [f.__dict__ for f in self.result.findings],
                "headers_by_url": self.result.headers_by_url,
                "cookies_by_url": self.result.cookies_by_url,
            }, f, indent=2, ensure_ascii=False)

        # Markdown (sorted by severity)
        sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        findings_sorted = sorted(self.result.findings, key=lambda x: (sev_order.get(x.severity, 9), x.type))
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(f"# VXScan+ Report

")
            f.write(f"**Target:** {self.result.target}  
")
            f.write(f"**Started:** {self.result.started}  
")
            f.write(f"**Finished:** {self.result.finished}  
")
            f.write(f"**Pages Crawled:** {self.result.pages_crawled}

")
            if not findings_sorted:
                f.write("## Findings

No issues detected by these checks.
")
            else:
                f.write("## Findings

")
                for i, fd in enumerate(findings_sorted, 1):
                    f.write(f"### {i}. {fd.type} — {fd.severity}
")
                    f.write(f"**URL:** {fd.url}

")
                    f.write(f"**Detail:** {fd.detail}

")
                    if fd.evidence:
                        ev = str(fd.evidence).replace("
", " ")
                        f.write(f"**Evidence:** `{ev[:400]}`

")
            f.write("
---

### Notes
")
            f.write("- This report is generated by an educational scanner. False positives/negatives are possible.
")
            f.write("- Validate findings manually and follow a responsible disclosure process.
")

        # HTML
        def sev_color(sev: str) -> str:
            return {
                "Critical": "#8b0000",
                "High": "#d9534f",
                "Medium": "#f0ad4e",
                "Low": "#5bc0de",
                "Info": "#5cb85c",
            }.get(sev, "#999")

        with open(html_path, "w", encoding="utf-8") as f:
            f.write("""<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>VXScan+ Report</title>
<style>
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Helvetica,Arial,sans-serif;padding:24px;background:#0b0e14;color:#e6edf3}
.table{width:100%;border-collapse:collapse;margin-top:16px}
.table th,.table td{border:1px solid #2d333b;padding:8px;vertical-align:top}
.table th{background:#161b22}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;color:#fff;font-size:12px}
small{color:#9aa7b0}
.card{background:#0f141a;border:1px solid #2d333b;border-radius:12px;padding:16px;margin-bottom:16px}
</style></head><body>""")
            f.write(f"<h1>VXScan+ Report</h1>")
            f.write(f"<div class='card'><div><b>Target:</b> {html.escape(self.result.target)}</div>" \
                    f"<div><b>Started:</b> {html.escape(self.result.started)}</div>" \
                    f"<div><b>Finished:</b> {html.escape(self.result.finished or '')}</div>" \
                    f"<div><b>Pages Crawled:</b> {self.result.pages_crawled}</div></div>")

            if not self.result.findings:
                f.write("<p>No issues detected by these checks.</p>")
            else:
                f.write("<table class='table'><thead><tr><th>#</th><th>Severity</th><th>Type</th><th>URL</th><th>Detail</th><th>Evidence</th></tr></thead><tbody>")
                for i, fd in enumerate(findings_sorted, 1):
                    f.write(
                        "<tr>" \
                        f"<td>{i}</td>" \
                        f"<td><span class='badge' style='background:{sev_color(fd.severity)}'>{html.escape(fd.severity)}</span></td>" \
                        f"<td>{html.escape(fd.type)}</td>" \
                        f"<td>{html.escape(fd.url)}</td>" \
                        f"<td>{html.escape(fd.detail)}</td>" \
                        f"<td><small>{html.escape((fd.evidence or '')[:400])}</small></td>" \
                        "</tr>"
                    )
                f.write("</tbody></table>")

            f.write("<div class='card'><b>Notes</b><ul>" \
                    "<li>Educational scanner; validate manually and report responsibly.</li>" \
                    "<li>Authenticated areas can be tested using the --cookie flag.</li>" \
                    "</ul></div>")
            f.write("</body></html>")

        return json_path, md_path, html_path

    # ---------- Run ----------
    def run(self, outdir: str = "reports"):
        print(C_INFO + f"[*] Crawling {self.base_url} (max_pages={self.max_pages}, depth={self.depth})")
        self.crawl()
        print(C_INFO + f"[*] Pages discovered: {len(self.visited)}")

        self.check_headers_and_cookies()
        self.check_sensitive_files()
        self.dir_bruteforce()
        self.test_forms_xss()
        self.test_sqli()
        self.test_lfi()
        self.test_open_redirect()

        json_path, md_path, html_path = self.save_reports(outdir=outdir)
        print(C_OK + "[+] Scan complete! Reports saved:")
        print("    JSON:", json_path)
        print("    MD  :", md_path)
        print("    HTML:", html_path)
        return json_path, md_path, html_path


# -----------------------------
# CLI
# -----------------------------

def main():
    ap = argparse.ArgumentParser(description="VXScan+ — improved educational web vulnerability scanner")
    ap.add_argument("--url", required=True, help="Target URL (e.g., https://example.com)")
    ap.add_argument("--max-pages", type=int, default=60, help="Max pages to crawl")
    ap.add_argument("--depth", type=int, default=2, help="Max link depth from start URL")
    ap.add_argument("--timeout", type=int, default=10, help="HTTP timeout seconds")
    ap.add_argument("--threads", type=int, default=8, help="Thread pool size")
    ap.add_argument("--cookie", help="Session cookie string for authenticated scanning")
    ap.add_argument("--payloads", help="Path to payloads.json to extend payloads")
    ap.add_argument("--outdir", default="reports", help="Output directory for reports")
    args = ap.parse_args()

    scanner = VXScan(
        args.url,
        max_pages=args.max_pages,
        depth=args.depth,
        timeout=args.timeout,
        threads=args.threads,
        cookie=args.cookie,
        payloads_file=args.payloads,
    )
    try:
        scanner.run(outdir=args.outdir)
    except KeyboardInterrupt:
        print("
Aborted by user.")
        sys.exit(1)


if __name__ == "__main__":
    main()
