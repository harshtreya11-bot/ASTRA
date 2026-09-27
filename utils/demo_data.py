"""
utils/demo_data.py - Synthetic demo log generator
"""

import random
import textwrap
from datetime import datetime, timedelta
from typing import List

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

NORMAL_IPS = ["203.0.113.10", "203.0.113.25", "198.51.100.5", "198.51.100.12"]
ATTACKER_IPS = ["192.168.1.20", "10.0.0.99", "172.16.0.50", "45.33.32.156"]
BRUTEFORCE_IP = "192.168.1.50"

NORMAL_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
]

ATTACK_UAS = [
    "sqlmap/1.7.8#stable",
    "Mozilla/5.0 (compatible; Nikto/2.1.6)",
    "python-requests/2.31.0",
    "curl/7.88.1",
    "Nuclei - Open-source project",
]

BASE_TIME = datetime(2026, 9, 25, 10, 30, 0)

# ---------------------------------------------------------------------------
# Payloads
# ---------------------------------------------------------------------------

SQLI_PAYLOADS = [
    "/login?username=admin%27%20OR%201%3D1--&password=x",
    "/login?username=%27%20OR%20%271%27%3D%271&password=wrong",
    "/search?q=%27%20UNION%20SELECT%201%2C2%2C3%2C4--",
    "/products?id=1%20UNION%20ALL%20SELECT%20NULL%2CNULL%2Ctable_name%20FROM%20information_schema.tables--",
    "/user?id=1%3BSELECT%20SLEEP(5)--",
    "/api/data?filter=1%3BDROP%20TABLE%20users--",
    "/items?sort=name%27%3BWAITFOR%20DELAY%20%270%3A0%3A5%27--",
    "/login?user=admin%27%20OR%20%27a%27%3D%27a",
    "/reports?date=2026-01-01%27%20AND%201%3D1--",
    "/search?term=test%27%20ORDER%20BY%201--",
]

XSS_PAYLOADS = [
    "/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "/comment?text=%3Cimg%20src%3Dx%20onerror%3Dalert(document.cookie)%3E",
    "/profile?name=%3Csvg%20onload%3Dalert(1)%3E",
    "/message?body=javascript%3Avoid(alert(1))",
    "/feedback?comment=%3Ciframe%20src%3Djavascript%3Aalert(%27XSS%27)%3E",
    "/search?q=%22%3E%3Cscript%3Eprompt(1)%3C%2Fscript%3E",
    "/user?bio=%3Ca%20href%3Djavascript%3Aalert(1)%3EClick%3C%2Fa%3E",
    "/post?title=%3Cscript%3Edocument.write(%27pwned%27)%3C%2Fscript%3E",
]

PATH_TRAVERSAL_PAYLOADS = [
    "/download?file=../../etc/passwd",
    "/file?name=..%2F..%2F..%2Fetc%2Fshadow",
    "/static?path=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2Fhosts",
    "/view?doc=..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "/img?src=../../../../var/log/apache2/access.log",
    "/resource?name=../../boot.ini",
    "/template?file=..%2F..%2F..%2Froot%2F.ssh%2Fid_rsa",
    "/export?path=../../etc/passwd",
]

CMDI_PAYLOADS = [
    "/ping?host=127.0.0.1%3Bwhoami",
    "/lookup?domain=example.com%7Cid",
    "/diagnostic?host=192.168.1.1%26%26cat%20/etc/passwd",
    "/check?ip=8.8.8.8%3Bls%20-la",
    "/trace?host=localhost%3B/bin/bash%20-i",
    "/network?addr=127.0.0.1%60whoami%60",
    "/util?cmd=ping%3B%24(id)",
    "/test?host=127.0.0.1%7Cpowershell%20-c%20whoami",
]

NORMAL_REQUESTS = [
    "GET / HTTP/1.1",
    "GET /products HTTP/1.1",
    "GET /about HTTP/1.1",
    "GET /contact HTTP/1.1",
    "GET /static/style.css HTTP/1.1",
    "GET /static/app.js HTTP/1.1",
    "GET /favicon.ico HTTP/1.1",
    "GET /images/logo.png HTTP/1.1",
    "GET /api/products?page=1&limit=10 HTTP/1.1",
    "GET /api/categories HTTP/1.1",
    "POST /login HTTP/1.1",
    "POST /contact/submit HTTP/1.1",
    "GET /search?q=laptop HTTP/1.1",
    "GET /search?q=phone+case HTTP/1.1",
    "GET /products?category=electronics HTTP/1.1",
    "GET /user/profile HTTP/1.1",
    "PUT /api/user/settings HTTP/1.1",
    "GET /blog/post-1 HTTP/1.1",
    "GET /blog/post-2 HTTP/1.1",
    "GET /docs/api HTTP/1.1",
]


def _fmt(ts: datetime, ip: str, method: str, path: str, status: int,
         size: int, ua: str, referer: str = "-") -> str:
    ts_str = ts.strftime("%d/%b/%Y:%H:%M:%S +0530")
    return (
        f'{ip} - - [{ts_str}] "{method} {path} HTTP/1.1" '
        f'{status} {size} "{referer}" "{ua}"'
    )


def generate_demo_log() -> str:
    """Generate a realistic synthetic access log with mixed traffic."""
    lines = []
    ts = BASE_TIME

    # --- 1. Normal traffic block ---
    for i in range(60):
        ip = random.choice(NORMAL_IPS)
        req = random.choice(NORMAL_REQUESTS)
        parts = req.split()
        method, path = parts[0], parts[1]
        ua = random.choice(NORMAL_UAS)
        status = 200 if random.random() > 0.05 else random.choice([301, 304, 404])
        size = random.randint(512, 8192)
        ts += timedelta(seconds=random.randint(1, 8))
        lines.append(_fmt(ts, ip, method, path, status, size, ua))

    # --- 2. SQL Injection campaign from 192.168.1.20 ---
    atk_ts = BASE_TIME + timedelta(minutes=1, seconds=2)
    for payload in SQLI_PAYLOADS:
        path_parts = payload.split("?", 1)
        path_clean = payload
        ua = random.choice(ATTACK_UAS)
        status = random.choice([200, 500, 403])
        size = random.randint(128, 2048)
        atk_ts += timedelta(seconds=random.randint(3, 12))
        lines.append(_fmt(atk_ts, "192.168.1.20", "GET", path_clean, status, size, ua))

    # --- 3. XSS attacks from 10.0.0.99 ---
    xss_ts = BASE_TIME + timedelta(minutes=2, seconds=5)
    for payload in XSS_PAYLOADS:
        ua = random.choice(ATTACK_UAS)
        status = random.choice([200, 400])
        size = random.randint(256, 4096)
        xss_ts += timedelta(seconds=random.randint(5, 15))
        lines.append(_fmt(xss_ts, "10.0.0.99", "GET", payload, status, size, ua))

    # --- 4. Path traversal from 172.16.0.50 ---
    pt_ts = BASE_TIME + timedelta(minutes=3, seconds=10)
    for payload in PATH_TRAVERSAL_PAYLOADS:
        ua = random.choice(ATTACK_UAS)
        status = random.choice([200, 403, 404])
        size = random.randint(64, 512)
        pt_ts += timedelta(seconds=random.randint(4, 10))
        lines.append(_fmt(pt_ts, "172.16.0.50", "GET", payload, status, size, ua))

    # --- 5. Command injection from 45.33.32.156 ---
    ci_ts = BASE_TIME + timedelta(minutes=4, seconds=20)
    for payload in CMDI_PAYLOADS:
        ua = random.choice(ATTACK_UAS)
        status = random.choice([200, 500])
        size = random.randint(64, 1024)
        ci_ts += timedelta(seconds=random.randint(3, 8))
        lines.append(_fmt(ci_ts, "45.33.32.156", "GET", payload, status, size, ua))

    # --- 6. Brute-force from 192.168.1.50 ---
    bf_ts = BASE_TIME + timedelta(minutes=1, seconds=30)
    for _ in range(25):
        bf_ts += timedelta(seconds=random.randint(3, 12))
        ua = random.choice(NORMAL_UAS)
        lines.append(_fmt(bf_ts, BRUTEFORCE_IP, "POST", "/login", 401, 512, ua))

    # One successful login after brute force (suspicious)
    bf_ts += timedelta(seconds=5)
    lines.append(_fmt(bf_ts, BRUTEFORCE_IP, "POST", "/login", 200, 1024, ua))

    # --- 7. Multi-vector attacker (192.168.1.20 also does other attacks) ---
    mv_ts = BASE_TIME + timedelta(minutes=3, seconds=0)
    for payload in XSS_PAYLOADS[:3]:
        mv_ts += timedelta(seconds=random.randint(10, 20))
        ua = random.choice(ATTACK_UAS)
        lines.append(_fmt(mv_ts, "192.168.1.20", "GET", payload, 200, 512, ua))
    for payload in PATH_TRAVERSAL_PAYLOADS[:2]:
        mv_ts += timedelta(seconds=random.randint(5, 15))
        ua = random.choice(ATTACK_UAS)
        lines.append(_fmt(mv_ts, "192.168.1.20", "GET", payload, 200, 256, ua))

    # --- 8. More normal traffic at the end ---
    end_ts = BASE_TIME + timedelta(minutes=5)
    for i in range(40):
        ip = random.choice(NORMAL_IPS)
        req = random.choice(NORMAL_REQUESTS)
        parts = req.split()
        method, path = parts[0], parts[1]
        ua = random.choice(NORMAL_UAS)
        status = 200
        size = random.randint(512, 6000)
        end_ts += timedelta(seconds=random.randint(1, 6))
        lines.append(_fmt(end_ts, ip, method, path, status, size, ua))

    # Sort by timestamp (already mostly sorted but shuffle-safe)
    def extract_ts(line: str) -> str:
        try:
            return line.split("[")[1].split("]")[0]
        except IndexError:
            return ""

    lines.sort(key=extract_ts)
    return "\n".join(lines)
