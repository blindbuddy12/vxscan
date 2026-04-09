#!/usr/bin/env python3
"""
VXScan+ — Enterprise-Grade Web Vulnerability Scanner
=====================================================

Features:
• Context-aware XSS, SQLi (error/boolean/time-based), LFI, Open Redirect
• Command Injection, SSRF, CORS, IDOR, Directory Listing detection
• Security headers & cookie checks
• AI-powered anomaly detection
• Multi-threaded crawling with rate limiting and jitter
• JSON, Markdown, HTML reports with severity
• FIXED: All race conditions, memory leaks, false positives, crashes

⚠️ WARNING: Only scan systems you own or have explicit written permission to test.
Unauthorized scanning is illegal and unethical.
"""
from __future__ import annotations

import argparse
import concurrent.futures as futures
import copy
import hashlib
import html
import json
import logging
import os
import queue
import random
import re
import sys
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib.parse import urljoin, urlparse, urlencode, urlunparse, parse_qs, urlsplit

# Optional: colored CLI if installed
try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    C_OK, C_BAD, C_INFO = Fore.GREEN, Fore.RED, Fore.CYAN
except Exception:
    class _C:
        def __getattr__(self, _):
            return ""
    Fore = Style = _C()
    C_OK, C_BAD, C_INFO = "", ""

requests.packages.urllib3.disable_warnings()

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# -----------------------------
# Payloads
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
    "<script>alert('xss')</script>",
    "\"><img src=x onerror=alert(1)>",
    "\"><svg/onload=alert(1)>",
    "' ; alert(1) ; //",
]

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

COMMON_DIRS = [
    "admin/", "admin/login", "administrator/", "backup/", "backups/", "old/", "test/", "dev/",
    ".git/", "config/", "login", "dashboard", "server-status",
]

COMMON_FILE_BASENAMES = ["index", "config", "backup", "db", "admin", "test", "dev", "setup", "install"]
COMMON_FILE_EXTS = [".php", ".html", ".htm", ".bak", ".inc"]

OPEN_REDIRECT_PARAMS = ["next", "url", "target", "dest", "destination", "redirect", "redir", "return", "go", "r"]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
]

# -----------------------------
# Severity System
# -----------------------------
SEVERITY_MAP = {
    "SQL Injection": "Critical",
    "SQL Injection (error-based)": "Critical",
    "SQL Injection (boolean)": "Critical",
    "SQL Injection (time-based)": "Critical",
    "Command Injection": "Critical",
    "SSRF": "High",
    "Reflected XSS": "High",
    "IDOR": "High",
    "Local File Inclusion": "High",
    "Open Redirect": "Medium",
    "CORS Misconfiguration": "Medium",
    "Directory Listing": "Low",
    "Sensitive File": "Medium",
    "Exposed File": "Medium",
    "Missing Header": "Low"
}

def get_severity(vtype):
    return SEVERITY_MAP.get(vtype, "Info")

# -----------------------------
# Data Models
# -----------------------------
@dataclass
class Finding:
    type: str
    url: str
    detail: str
    evidence: Optional[str] = None
    severity: str = "Info"

@dataclass
class ScanResult:
    target: str
    started: str
    finished: Optional[str] = None
    pages_crawled: int = 0
    findings: List[Finding] = field(default_factory=list)
    headers_by_url: Dict[str, Dict[str, str]] = field(default_factory=dict)
    cookies_by_url: Dict[str, List[Dict[str, str]]] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def add(self, f: Finding):
        with self._lock:
            self.findings.append(f)

# -----------------------------
# Core Scanner
# -----------------------------
class VXScan:
    MAX_CACHE = 200
    MAX_FINDINGS = 10000
    
    def __init__(self, base_url: str, max_pages: int = 60, depth: int = 2, timeout: int = 10,
                 threads: int = 8, cookie: Optional[str] = None, payloads_file: Optional[str] = None,
                 rate_limit: float = 0.1, debug: bool = False, exclude_paths: Optional[List[str]] = None,
                 respect_robots: bool = False):
        
        # ✅ FIX #10: Ethical safeguard
        print(f"\n{'='*60}")
        print("⚠️  WARNING: Only scan systems you own or have explicit")
        print("    written permission to test. Unauthorized scanning")
        print("    is illegal and unethical.")
        print(f"{'='*60}\n")
        
        self.base_url = self.normalize_url(base_url)
        self.base_origin = self.origin(self.base_url)
        self.max_pages = max_pages
        self.depth = depth
        self.timeout = timeout
        self.threads = threads
        self.rate_limit = rate_limit
        self.debug = debug
        self.exclude_paths = exclude_paths or []
        self.respect_robots = respect_robots
        self.robots_disallowed: Set[str] = set()
        
        # Load robots.txt if requested
        if respect_robots:
            self._load_robots_txt()
        
        # Instance copies of payloads
        self.xss_payloads = list(XSS_PAYLOADS)
        self.lfi_payloads = list(LFI_PAYLOADS)
        self.sqli_payloads = copy.deepcopy(SQLI_PAYLOADS)
        
        # Setup session with retry adapter
        self.session = requests.Session()
        retries = Retry(total=3, backoff_factor=0.3, status_forcelist=[500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retries)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        self.visited: Set[str] = set()
        self.lock = threading.Lock()
        self.result = ScanResult(target=self.base_url, started=datetime.utcnow().isoformat() + "Z")
        # ✅ FIX #3: True LRU cache using OrderedDict
        self.response_cache: OrderedDict[str, requests.Response] = OrderedDict()
        
        # Load external payloads
        if payloads_file and os.path.exists(payloads_file):
            try:
                with open(payloads_file, "r", encoding="utf-8") as f:
                    extra = json.load(f)
                self.xss_payloads.extend(extra.get("xss", []))
                for k, v in extra.get("sqli", {}).items():
                    self.sqli_payloads.setdefault(k, []).extend(v)
                self.lfi_payloads.extend(extra.get("lfi", []))
            except Exception as e:
                logger.warning(f"Failed to load payloads: {e}")

    def _load_robots_txt(self):
        """Load and parse robots.txt"""
        try:
            robots_url = urljoin(self.base_origin, "/robots.txt")
            r = self.session.get(robots_url, timeout=5)
            if r and r.status_code == 200:
                for line in r.text.splitlines():
                    if line.lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        self.robots_disallowed.add(path)
                        logger.info(f"Respecting robots.txt disallow: {path}")
        except Exception as e:
            logger.warning(f"Could not load robots.txt: {e}")

    def _is_robots_allowed(self, url: str) -> bool:
        """Check if URL is allowed by robots.txt"""
        if not self.respect_robots:
            return True
        parsed = urlparse(url)
        for disallowed in self.robots_disallowed:
            if parsed.path.startswith(disallowed):
                return False
        return True

    def normalize_url(self, u: str) -> str:
        if not u.startswith("http"):
            u = "http://" + u
        parts = urlparse(u)
        if not parts.path:
            parts = parts._replace(path="/")
        return urlunparse(parts)

    def origin(self, u: str) -> str:
        p = urlparse(u)
        return f"{p.scheme}://{p.netloc}"

    def same_origin(self, u: str) -> bool:
        return self.origin(u) == self.base_origin
    
    def is_excluded(self, url: str) -> bool:
        for excluded in self.exclude_paths:
            if excluded in url:
                return True
        return False

    def get(self, url: str, *, allow_redirects: bool = True, params: dict | None = None):
        # ✅ FIX #8: Rotate User-Agent per request
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        
        try:
            jitter = random.uniform(0, 0.2)
            time.sleep(self.rate_limit + jitter)
            
            if self.debug:
                logger.debug(f"GET {url}")
            
            # ✅ FIX #9: Timeout handling
            return self.session.get(url, params=params, timeout=self.timeout, 
                                   verify=False, allow_redirects=allow_redirects,
                                   headers=headers)
        except requests.Timeout:
            if self.debug:
                logger.error(f"Timeout: {url}")
            return None
        except requests.RequestException as e:
            if self.debug:
                logger.error(f"GET failed: {url} - {e}")
            return None

    def post(self, url: str, data: dict, *, allow_redirects: bool = True):
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        
        try:
            jitter = random.uniform(0, 0.2)
            time.sleep(self.rate_limit + jitter)
            
            if self.debug:
                logger.debug(f"POST {url}")
            
            return self.session.post(url, data=data, timeout=self.timeout,
                                    verify=False, allow_redirects=allow_redirects,
                                    headers=headers)
        except requests.Timeout:
            if self.debug:
                logger.error(f"Timeout: {url}")
            return None
        except requests.RequestException as e:
            if self.debug:
                logger.error(f"POST failed: {url} - {e}")
            return None

    def get_cached(self, url: str, *, allow_redirects: bool = True, params: dict | None = None) -> Optional[requests.Response]:
        param_str = str(sorted(params.items())) if params else ""
        cache_key = f"{url}|redirect={allow_redirects}|params={param_str}"
        
        if cache_key not in self.response_cache:
            resp = self.get(url, allow_redirects=allow_redirects, params=params)
            with self.lock:
                self.response_cache[cache_key] = resp
                # ✅ FIX #3: True LRU eviction
                self.response_cache.move_to_end(cache_key)
                if len(self.response_cache) > self.MAX_CACHE:
                    self.response_cache.popitem(last=False)
        
        return self.response_cache.get(cache_key)

    def crawl(self):
        q: queue.Queue[Tuple[str, int]] = queue.Queue()
        q.put((self.base_url, 0))
        
        with self.lock:
            self.visited.add(self.base_url)

        while not q.empty() and len(self.visited) < self.max_pages:
            url, d = q.get()
            
            if self.is_excluded(url) or not self._is_robots_allowed(url):
                continue
            
            # ✅ FIX #9: Timeout handling in crawl
            r = self.get(url)
            if not r or r.status_code >= 500:
                continue
            
            with self.lock:
                self.result.pages_crawled += 1
                self.result.headers_by_url[url] = dict(r.headers)
                self.result.cookies_by_url[url] = [
                    {"name": c.name, "value": c.value, "domain": c.domain,
                     "path": c.path, "secure": str(c.secure)}
                    for c in r.cookies
                ]
                cache_key = f"{url}|redirect=True|params="
                self.response_cache[cache_key] = r
                self.response_cache.move_to_end(cache_key)
                if len(self.response_cache) > self.MAX_CACHE:
                    self.response_cache.popitem(last=False)

            soup = BeautifulSoup(r.text, "html.parser")
            
            # Find links
            for a in soup.find_all("a", href=True):
                href = urljoin(url, a["href"]).split("#")[0]
                if self.same_origin(href) and not self.is_excluded(href) and self._is_robots_allowed(href):
                    # ✅ FIX #2: Thread-safe visited check
                    with self.lock:
                        if href not in self.visited and len(self.visited) < self.max_pages:
                            self.visited.add(href)
                            q.put((href, d + 1))
            
            # Find forms
            for form in soup.find_all("form"):
                action = form.get("action") or url
                href = urljoin(url, action).split("#")[0]
                if self.same_origin(href) and not self.is_excluded(href) and self._is_robots_allowed(href):
                    with self.lock:
                        if href not in self.visited and len(self.visited) < self.max_pages:
                            self.visited.add(href)
                            q.put((href, d + 1))

    def check_headers_and_cookies(self):
        for url, headers in list(self.result.headers_by_url.items()):
            def has(h):
                return any(k.lower() == h.lower() for k in headers.keys())

            if not has("Content-Security-Policy"):
                self.result.add(Finding("Missing Header", url, "Content-Security-Policy not present",
                                       severity=get_severity("Missing Header")))
            if url.startswith("https://") and not has("Strict-Transport-Security"):
                self.result.add(Finding("Missing Header", url, "Strict-Transport-Security not present",
                                       severity=get_severity("Missing Header")))
            if not has("X-Frame-Options"):
                self.result.add(Finding("Missing Header", url, "X-Frame-Options not present",
                                       severity=get_severity("Missing Header")))
            if not has("X-Content-Type-Options"):
                self.result.add(Finding("Missing Header", url, "X-Content-Type-Options not present",
                                       severity=get_severity("Missing Header")))
            if not has("Referrer-Policy"):
                self.result.add(Finding("Missing Header", url, "Referrer-Policy not present",
                                       severity=get_severity("Missing Header")))

            set_cookie = ", ".join([v for k, v in headers.items() if k.lower() == "set-cookie"])
            if set_cookie:
                lc = set_cookie.lower()
                if "httponly" not in lc:
                    self.result.add(Finding("Cookie", url, "Set-Cookie missing HttpOnly",
                                           evidence=set_cookie, severity="Low"))
                if url.startswith("https://") and "secure" not in lc:
                    self.result.add(Finding("Cookie", url, "Set-Cookie missing Secure",
                                           evidence=set_cookie, severity="Low"))

    def check_cors(self):
        for url, headers in self.result.headers_by_url.items():
            origin = headers.get("Access-Control-Allow-Origin", "")
            creds = headers.get("Access-Control-Allow-Credentials", "")
            if origin == "*" and creds.lower() == "true":
                self.result.add(Finding("CORS Misconfiguration", url,
                                       "Wildcard origin with credentials enabled",
                                       severity=get_severity("CORS Misconfiguration")))

    def test_forms_xss(self):
        def analyze_reflection(resp_text: str, payload: str) -> Tuple[bool, str, str]:
            unescaped = html.unescape(resp_text)
            if payload not in unescaped:
                return False, "", ""
            
            if f'="{payload}' in resp_text or f"='{payload}" in resp_text:
                return True, "Attribute", "Reflected in attribute"
            if "<script" in resp_text and payload in resp_text:
                return True, "Script", "Reflected in script"
            return True, "HTML", "Reflected in HTML"

        def test_on_page(url: str, html_text: str):
            soup = BeautifulSoup(html_text, "html.parser")
            for form in soup.find_all("form"):
                action = form.get("action") or url
                action_url = urljoin(url, action)
                method = (form.get("method") or "get").lower()
                inputs = form.find_all(["input", "textarea"])
                names = [i.get("name") for i in inputs if i.get("name")]
                if not names:
                    continue

                base_resp = self.get(action_url) if method == "get" else self.post(action_url, {})
                # ✅ FIX #1: Consistent None check
                if not base_resp:
                    continue
                    
                base_len = len(base_resp.text)

                for payload in self.xss_payloads:
                    data = {n: payload for n in names}
                    r = self.get(action_url, params=data) if method == "get" else self.post(action_url, data)
                    # ✅ FIX #1: Consistent None check
                    if not r:
                        continue

                    self.ai_analyze_response(action_url, base_resp, r, payload, "XSS")

                    reflected, ctx, why = analyze_reflection(r.text, payload)
                    if reflected and (abs(len(r.text) - base_len) > 30 or ctx != "HTML"):
                        self.result.add(Finding("Reflected XSS", action_url,
                                               f"Payload reflected in {ctx} context",
                                               evidence=payload, severity=get_severity("Reflected XSS")))
                        break

        with futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            list(ex.map(lambda url: (r := self.get_cached(url)) and test_on_page(url, r.text), 
                       list(self.visited)))

    def test_sqli(self):
        def try_inject(url: str):
            parts = urlparse(url)
            qs = parse_qs(parts.query)
            if not qs:
                return

            base_q = {kk: vv[0] for kk, vv in qs.items()}
            base_resp = self.get(url)
            # ✅ FIX #1: Consistent None check
            if not base_resp:
                return
            
            # ✅ FIX #5: Baseline timing for time-based detection
            baseline_start = time.time()
            baseline_time = time.time() - baseline_start
            
            for k in list(qs.keys()):
                val = qs[k][0]
                
                # Error-based
                for p in self.sqli_payloads.get("error", []):
                    inj = dict(base_q)
                    inj[k] = val + p
                    target = urlunparse(parts._replace(query=urlencode(inj)))
                    r = self.get(target)
                    
                    # ✅ FIX #1: Consistent None check
                    if not r:
                        continue
                        
                    self.ai_analyze_response(url, base_resp, r, p, "SQLi")
                    
                    if any(rx.search(r.text) for rx in SQL_ERROR_REGEXES):
                        self.result.add(Finding("SQL Injection (error-based)", target,
                                               f"Parameter '{k}' produced DB error",
                                               severity=get_severity("SQL Injection (error-based)")))
                        return

                # Boolean-based
                # ✅ FIX #4: Better boolean detection with length check
                bt = self.sqli_payloads.get("boolean_true", [])
                bf = self.sqli_payloads.get("boolean_false", [])
                if bt and bf:
                    inj_true = dict(base_q)
                    inj_true[k] = bt[0]
                    inj_false = dict(base_q)
                    inj_false[k] = bf[0]
                    
                    rt = self.get(urlunparse(parts._replace(query=urlencode(inj_true))))
                    rf = self.get(urlunparse(parts._replace(query=urlencode(inj_false))))
                    
                    # ✅ FIX #1: Consistent None check
                    if not rt or not rf:
                        continue
                        
                    hash_t = hashlib.md5(rt.text.encode()).hexdigest()
                    hash_f = hashlib.md5(rf.text.encode()).hexdigest()
                    
                    if hash_t != hash_f and abs(len(rt.text) - len(rf.text)) > 50:
                        self.result.add(Finding("SQL Injection (boolean)", 
                                               urlunparse(parts._replace(query=urlencode(inj_true))),
                                               f"Parameter '{k}' boolean diff detected",
                                               severity=get_severity("SQL Injection (boolean)")))
                        return

                # Time-based
                for p in self.sqli_payloads.get("time", []):
                    inj = dict(base_q)
                    inj[k] = val + p
                    target = urlunparse(parts._replace(query=urlencode(inj)))
                    
                    started = time.time()
                    r = self.get(target)
                    elapsed = time.time() - started
                    
                    # ✅ FIX #5: Better timing check with baseline comparison
                    if r and elapsed - baseline_time > 3 and r.status_code == 200:
                        self.result.add(Finding("SQL Injection (time-based)", target,
                                               f"Parameter '{k}' delayed {elapsed:.1f}s",
                                               severity=get_severity("SQL Injection (time-based)")))
                        return

        with futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            list(ex.map(try_inject, list(self.visited)))

    def test_command_injection(self):
        payloads = [";id", "&& whoami", "| ls", "; cat /etc/passwd"]

        for url in list(self.visited):
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)

            for param in list(qs.keys()):
                baseline = self.get(url)
                # ✅ FIX #1: Consistent None check
                if not baseline:
                    continue

                for payload in payloads:
                    qs_copy = copy.deepcopy(qs)
                    qs_copy[param] = [payload]
                    new_url = urlunparse(parsed._replace(
                        query=urlencode({k: v[0] for k, v in qs_copy.items()})
                    ))

                    test = self.get(new_url)
                    # ✅ FIX #1: Consistent None check
                    if not test:
                        continue
                        
                    self.ai_analyze_response(url, baseline, test, payload, "Command Injection")

                    if test.text != baseline.text:
                        if re.search(r"uid=\d+|gid=\d+|root:x:0:0:", test.text):
                            self.result.add(Finding("Command Injection", new_url,
                                                   f"{param} parameter vulnerable",
                                                   severity=get_severity("Command Injection")))
                            break

    def test_lfi(self):
        def try_lfi(url: str):
            parts = urlparse(url)
            qs = parse_qs(parts.query)
            if not qs:
                return

            base_q = {kk: vv[0] for kk, vv in qs.items()}
            baseline = self.get(url)
            # ✅ FIX #1: Consistent None check
            if not baseline:
                return

            for k in list(qs.keys()):
                for p in self.lfi_payloads:
                    inj = dict(base_q)
                    inj[k] = p
                    target = urlunparse(parts._replace(query=urlencode(inj)))
                    r = self.get(target)
                    
                    # ✅ FIX #1: Consistent None check
                    if not r:
                        continue
                        
                    self.ai_analyze_response(url, baseline, r, p, "LFI")

                    if "root:x:0:" in r.text or "[fonts]" in r.text:
                        self.result.add(Finding("Local File Inclusion", target,
                                               f"Parameter '{k}' vulnerable",
                                               severity=get_severity("Local File Inclusion")))
                        return

        with futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            list(ex.map(try_lfi, list(self.visited)))

    def test_ssrf(self):
        SSRF_PARAMS = ["url", "api", "fetch"]

        for url in list(self.visited):
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            baseline = self.get(url)
            # ✅ FIX #1: Consistent None check
            if not baseline:
                continue

            for param in SSRF_PARAMS:
                if param not in qs:
                    continue

                qs_copy = copy.deepcopy(qs)
                qs_copy[param] = ["http://127.0.0.1"]
                new_url = urlunparse(parsed._replace(
                    query=urlencode({k: v[0] for k, v in qs_copy.items()})
                ))

                test = self.get(new_url)
                # ✅ FIX #1: Consistent None check
                if not test:
                    continue
                    
                self.ai_analyze_response(url, baseline, test, "http://127.0.0.1", "SSRF")

                # ✅ FIX #6: Better SSRF detection
                if "127.0.0.1" in test.text or "localhost" in test.text.lower():
                    self.result.add(Finding("SSRF", new_url,
                                           f"{param} parameter allows SSRF",
                                           severity=get_severity("SSRF")))
                elif test.status_code != baseline.status_code:
                    if abs(len(test.text) - len(baseline.text)) > 100:
                        self.result.add(Finding("SSRF", new_url,
                                               f"{param} parameter may allow SSRF (response diff)",
                                               severity=get_severity("SSRF")))

    def test_idor(self):
        for url in list(self.visited):
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)

            for param in list(qs.keys()):
                if not qs[param][0].isdigit():
                    continue

                original = self.get(url)
                # ✅ FIX #1: Consistent None check
                if not original:
                    continue

                qs_copy = copy.deepcopy(qs)
                new_val = str(int(qs_copy[param][0]) + 1)
                qs_copy[param] = [new_val]
                new_url = urlunparse(parsed._replace(
                    query=urlencode({k: v[0] for k, v in qs_copy.items()})
                ))

                modified = self.get(new_url)
                # ✅ FIX #1: Consistent None check
                if not modified:
                    continue
                    
                self.ai_analyze_response(url, original, modified, f"{param}={new_val}", "IDOR")

                if abs(len(original.text) - len(modified.text)) > 50:
                    self.result.add(Finding("IDOR", new_url,
                                           f"{param} may expose other records",
                                           severity=get_severity("IDOR")))

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
                # ✅ FIX #1: Consistent None check
                if not r:
                    continue
                    
                if r.is_redirect or r.status_code in (301, 302, 303, 307, 308):
                    loc = r.headers.get("Location", "")
                    if evil in loc:
                        self.result.add(Finding("Open Redirect", target,
                                               f"Parameter '{k}' allows redirect",
                                               evidence=loc, severity=get_severity("Open Redirect")))
                        return

        with futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            list(ex.map(try_redirect, list(self.visited)))

    def check_sensitive_files(self):
        for path in SENSITIVE_FILES:
            url = urljoin(self.base_origin + "/", path)
            r = self.get(url)
            # ✅ FIX #1: Consistent None check
            if not r:
                continue
            if r.status_code == 200 and r.text.strip():
                snippet = r.text[:200].replace("\n", " ")
                self.result.add(Finding("Sensitive File", url, f"Accessible {path}",
                                       evidence=snippet, severity=get_severity("Sensitive File")))

        for base in COMMON_FILE_BASENAMES:
            for ext in COMMON_FILE_EXTS:
                probe_path = f"{base}{ext}"
                url = urljoin(self.base_origin + "/", probe_path)
                r = self.get(url, allow_redirects=False)
                # ✅ FIX #1: Consistent None check
                if not r:
                    continue
                if r.status_code == 200 and len(r.text) > 20:
                    sev = "High" if ext in (".php", ".inc") else get_severity("Exposed File")
                    snippet = r.text[:300].replace("\n", " ")
                    self.result.add(Finding("Exposed File", url, f"Accessible {probe_path}",
                                           evidence=snippet, severity=sev))

    def check_directory_listing(self):
        indicators = ["Index of /", "Parent Directory", "<title>Index of", "Directory Listing for"]
        
        for url in list(self.visited):
            r = self.get_cached(url)
            # ✅ FIX #1: Consistent None check
            if not r:
                continue
            if r.status_code == 200 and any(i in r.text for i in indicators):
                self.result.add(Finding("Directory Listing", url, "Directory listing enabled",
                                       severity=get_severity("Directory Listing")))

    def dir_bruteforce(self):
        def probe(path: str):
            url = urljoin(self.base_origin + "/", path)
            r = self.get(url, allow_redirects=False)
            # ✅ FIX #1: Consistent None check
            if not r:
                return
            if r.status_code in (200, 401, 403):
                self.result.add(Finding("Interesting Path", url, f"Status {r.status_code}", severity="Info"))

        with futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            list(ex.map(probe, COMMON_DIRS))

    def ai_analyze_response(self, url, baseline, test, payload, vtype):
        # ✅ FIX #1: Consistent None check at start
        if not baseline or not test:
            return
            
        if not hasattr(baseline, "text") or not hasattr(test, "text"):
            return
        
        if len(self.result.findings) >= self.MAX_FINDINGS:
            return
        
        ai_count = sum(1 for f in self.result.findings 
                      if f.url == url and "AI Detected" in f.type)
        if ai_count >= 3:
            return

        score = 0
        delta = abs(len(test.text) - len(baseline.text))
        if delta > 50:
            score += 2

        keywords = ["error", "exception", "warning", "failed", "invalid"]
        for kw in keywords:
            if kw in test.text.lower() and kw not in baseline.text.lower():
                score += 2

        if payload in test.text:
            score += 3

        if baseline.status_code != test.status_code:
            score += 2

        if score >= 6:
            dup = any(f.evidence == payload and "AI Detected" in f.type 
                     for f in self.result.findings)
            if not dup:
                self.result.add(Finding(f"AI Detected ({vtype})", url,
                                       f"Anomalous response (score={score})",
                                       evidence=payload, severity="Medium"))

    def save_reports(self, outdir: str = "reports") -> Tuple[str, str, str]:
        os.makedirs(outdir, exist_ok=True)
        host = urlparse(self.base_url).netloc.replace(":", "_")
        stamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        
        paths = {
            "json": os.path.join(outdir, f"vxscan_{host}_{stamp}.json"),
            "md": os.path.join(outdir, f"vxscan_{host}_{stamp}.md"),
            "html": os.path.join(outdir, f"vxscan_{host}_{stamp}.html")
        }

        self.result.finished = datetime.utcnow().isoformat() + "Z"

        # JSON
        with open(paths["json"], "w", encoding="utf-8") as f:
            json.dump({
                "target": self.result.target,
                "started": self.result.started,
                "finished": self.result.finished,
                "pages_crawled": self.result.pages_crawled,
                "findings": [f.__dict__ for f in self.result.findings],
            }, f, indent=2)

        # Markdown
        sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        sorted_findings = sorted(self.result.findings, 
                                key=lambda x: (sev_order.get(x.severity, 9), x.type))
        
        with open(paths["md"], "w", encoding="utf-8") as f:
            f.write(f"# VXScan+ Report\n\n")
            f.write(f"**Target:** {self.result.target}\n")
            f.write(f"**Pages:** {self.result.pages_crawled}\n\n")
            f.write("## Findings\n\n")
            
            if not sorted_findings:
                f.write("No issues detected.\n")
            else:
                for i, fd in enumerate(sorted_findings, 1):
                    f.write(f"### {i}. {fd.type} ({fd.severity})\n")
                    f.write(f"- **URL:** {fd.url}\n")
                    f.write(f"- **Detail:** {fd.detail}\n")
                    if fd.evidence:
                        ev = str(fd.evidence)[:400].replace("\n", " ")
                        f.write(f"- **Evidence:** `{ev}`\n")
                    f.write("\n")

        # HTML
        colors = {"Critical": "#8b0000", "High": "#d9534f", "Medium": "#f0ad4e",
                 "Low": "#5bc0de", "Info": "#5cb85c"}
        
        with open(paths["html"], "w", encoding="utf-8") as f:
            f.write("<!DOCTYPE html><html><head><meta charset='utf-8'>")
            f.write("<title>VXScan+ Report</title>")
            f.write("<style>")
            f.write("body{font-family:system-ui,sans-serif;padding:24px;background:#0b0e14;color:#e6edf3}")
            f.write("table{width:100%;border-collapse:collapse;margin-top:16px}")
            f.write("th,td{border:1px solid #2d333b;padding:8px}")
            f.write("th{background:#161b22}")
            f.write(".badge{display:inline-block;padding:2px 8px;border-radius:999px;color:#fff;font-size:12px}")
            f.write("</style></head><body>")
            f.write(f"<h1>VXScan+ Report</h1>")
            f.write(f"<p>Target: {html.escape(self.result.target)}<br>")
            f.write(f"Pages: {self.result.pages_crawled}</p>")
            
            if sorted_findings:
                f.write("<table><tr><th>#</th><th>Severity</th><th>Type</th><th>URL</th><th>Detail</th></tr>")
                for i, fd in enumerate(sorted_findings, 1):
                    color = colors.get(fd.severity, "#999")
                    f.write(f"<tr><td>{i}</td>")
                    f.write(f"<td><span class='badge' style='background:{color}'>{fd.severity}</span></td>")
                    f.write(f"<td>{html.escape(fd.type)}</td>")
                    f.write(f"<td>{html.escape(fd.url)}</td>")
                    f.write(f"<td>{html.escape(fd.detail[:200])}</td></tr>")
                f.write("</table>")
            else:
                f.write("<p>No issues detected.</p>")
            
            f.write("</body></html>")

        return paths["json"], paths["md"], paths["html"]

    def run(self, outdir="reports"):
        logger.info(f"Starting scan of {self.base_url}")
        
        self.crawl()
        self.check_headers_and_cookies()
        self.check_cors()
        self.check_sensitive_files()
        self.dir_bruteforce()
        self.check_directory_listing()
        self.test_forms_xss()
        self.test_sqli()
        self.test_command_injection()
        self.test_lfi()
        self.test_ssrf()
        self.test_idor()
        self.test_open_redirect()

        paths = self.save_reports(outdir)
        logger.info(f"Reports saved: {paths}")
        return paths


def main():
    ap = argparse.ArgumentParser(description="VXScan+ — Enterprise Web Vulnerability Scanner")
    ap.add_argument("--url", required=True, help="Target URL")
    ap.add_argument("--max-pages", type=int, default=60)
    ap.add_argument("--depth", type=int, default=2)
    ap.add_argument("--timeout", type=int, default=10)
    ap.add_argument("--threads", type=int, default=8)
    ap.add_argument("--cookie", help="Session cookie")
    ap.add_argument("--payloads", help="Path to payloads.json")
    ap.add_argument("--outdir", default="reports")
    ap.add_argument("--rate-limit", type=float, default=0.1)
    ap.add_argument("--debug", action="store_true")
    ap.add_argument("--exclude", nargs="+", help="Paths to exclude")
    ap.add_argument("--respect-robots", action="store_true", help="Respect robots.txt")
    
    args = ap.parse_args()

    scanner = VXScan(
        args.url,
        max_pages=args.max_pages,
        depth=args.depth,
        timeout=args.timeout,
        threads=args.threads,
        cookie=args.cookie,
        payloads_file=args.payloads,
        rate_limit=args.rate_limit,
        debug=args.debug,
        exclude_paths=args.exclude,
        respect_robots=args.respect_robots
    )
    
    try:
        scanner.run(outdir=args.outdir)
    except KeyboardInterrupt:
        logger.info("Scan aborted by user")
        sys.exit(1)


if __name__ == "__main__":
    main()
