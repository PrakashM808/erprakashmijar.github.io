"""
web_scanner.py — Website & Domain Security Scanner
Checks: SSL/TLS, HTTP headers, DNS (SPF/DMARC/DKIM), exposed files,
        tech fingerprint, port scan, subdomain hints
"""
import socket
import ssl
import re
import json
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Optional


# ── SSL / TLS ────────────────────────────────────────────────────

def check_ssl(domain: str, port: int = 443) -> dict:
    result = {"valid": False, "expired": False, "days_left": None,
              "issuer": None, "subject": None, "version": None,
              "cipher": None, "error": None}
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((domain, port), timeout=8),
                             server_hostname=domain) as s:
            cert = s.getpeercert()
            cipher = s.cipher()
            result["valid"]   = True
            result["version"] = s.version()
            result["cipher"]  = cipher[0] if cipher else None
            result["subject"] = dict(x[0] for x in cert.get("subject", []))
            result["issuer"]  = dict(x[0] for x in cert.get("issuer",  []))
            not_after  = cert.get("notAfter", "")
            not_before = cert.get("notBefore", "")
            if not_after:
                exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days = (exp - datetime.now(timezone.utc)).days
                result["days_left"] = days
                result["expired"]   = days < 0
                result["expires"]   = not_after
            result["san"] = [v for _, v in cert.get("subjectAltName", [])]
    except ssl.SSLCertVerificationError as e:
        result["error"] = f"Certificate verification failed: {e}"
    except ssl.SSLError as e:
        result["error"] = f"SSL error: {e}"
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        result["error"] = f"Connection failed: {e}"
    except Exception as e:
        result["error"] = str(e)
    return result


# ── HTTP SECURITY HEADERS ────────────────────────────────────────

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "desc": "Forces HTTPS — prevents downgrade attacks",
        "severity": "high",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
    },
    "Content-Security-Policy": {
        "desc": "Prevents XSS and data injection attacks",
        "severity": "high",
        "recommendation": "Add a CSP policy: Content-Security-Policy: default-src 'self'"
    },
    "X-Frame-Options": {
        "desc": "Prevents clickjacking attacks",
        "severity": "medium",
        "recommendation": "Add: X-Frame-Options: DENY"
    },
    "X-Content-Type-Options": {
        "desc": "Prevents MIME-type sniffing",
        "severity": "medium",
        "recommendation": "Add: X-Content-Type-Options: nosniff"
    },
    "Referrer-Policy": {
        "desc": "Controls referrer information leakage",
        "severity": "low",
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin"
    },
    "Permissions-Policy": {
        "desc": "Controls browser feature access",
        "severity": "low",
        "recommendation": "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()"
    },
    "X-XSS-Protection": {
        "desc": "Legacy XSS filter (modern browsers use CSP)",
        "severity": "low",
        "recommendation": "Add: X-XSS-Protection: 1; mode=block"
    },
}

def check_http_headers(url: str) -> dict:
    if not url.startswith("http"):
        url = "https://" + url
    result = {"url": url, "status_code": None, "server": None,
              "headers_present": [], "headers_missing": [], "raw": {}}
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 SecurityScanner/1.0"})
        with urllib.request.urlopen(req, timeout=10) as r:
            result["status_code"] = r.status
            headers = dict(r.headers)
            result["raw"] = headers
            result["server"] = headers.get("Server", headers.get("server"))
            for h, info in SECURITY_HEADERS.items():
                found = any(k.lower() == h.lower() for k in headers)
                entry = {**info, "header": h, "value": headers.get(h, headers.get(h.lower()))}
                if found:
                    result["headers_present"].append(entry)
                else:
                    result["headers_missing"].append(entry)
    except urllib.error.HTTPError as e:
        result["status_code"] = e.code
        result["error"] = f"HTTP {e.code}"
        try:
            headers = dict(e.headers)
            for h, info in SECURITY_HEADERS.items():
                found = any(k.lower() == h.lower() for k in headers)
                entry = {**info, "header": h}
                (result["headers_present"] if found else result["headers_missing"]).append(entry)
        except:
            pass
    except Exception as e:
        result["error"] = str(e)
    return result


# ── DNS SECURITY ─────────────────────────────────────────────────

def check_dns_security(domain: str) -> dict:
    import subprocess
    result = {"spf": None, "dmarc": None, "dkim_hint": None,
              "mx": [], "ns": [], "a_records": [], "issues": []}
    def dig(qtype: str, name: str) -> str:
        try:
            r = subprocess.run(["dig", "+short", qtype, name], capture_output=True, text=True, timeout=8)
            return r.stdout.strip()
        except:
            try:
                r = subprocess.run(["nslookup", f"-type={qtype}", name], capture_output=True, text=True, timeout=8)
                return r.stdout
            except:
                return ""

    # SPF
    txt = dig("TXT", domain)
    spf_match = re.search(r'"(v=spf1[^"]*)"', txt)
    if spf_match:
        spf = spf_match.group(1)
        result["spf"] = {"record": spf, "valid": True,
                         "all_mechanism": "~all" in spf or "-all" in spf,
                         "soft_fail": "~all" in spf, "hard_fail": "-all" in spf}
    else:
        result["spf"] = {"record": None, "valid": False}
        result["issues"].append({"severity": "high", "issue": "No SPF record found",
            "detail": "Anyone can send email pretending to be from this domain",
            "fix": f'Add TXT record: v=spf1 include:_spf.google.com -all'})

    # DMARC
    dmarc_raw = dig("TXT", f"_dmarc.{domain}")
    dmarc_match = re.search(r'"(v=DMARC1[^"]*)"', dmarc_raw)
    if dmarc_match:
        dmarc = dmarc_match.group(1)
        policy = re.search(r'p=(\w+)', dmarc)
        rua    = re.search(r'rua=([^;]+)', dmarc)
        result["dmarc"] = {"record": dmarc, "valid": True,
                           "policy": policy.group(1) if policy else "none",
                           "reporting": rua.group(1) if rua else None}
        if policy and policy.group(1) == "none":
            result["issues"].append({"severity": "medium", "issue": "DMARC policy is 'none' — monitoring only",
                "detail": "Emails can still be spoofed — policy does not reject or quarantine",
                "fix": "Change DMARC policy to p=quarantine or p=reject"})
    else:
        result["dmarc"] = {"record": None, "valid": False}
        result["issues"].append({"severity": "high", "issue": "No DMARC record found",
            "detail": "No email authentication policy — domain is vulnerable to spoofing",
            "fix": f'Add TXT record at _dmarc.{domain}: v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}'})

    # MX
    mx_raw = dig("MX", domain)
    result["mx"] = [line.strip() for line in mx_raw.split('\n') if line.strip()]

    # A records
    a_raw = dig("A", domain)
    result["a_records"] = [line.strip() for line in a_raw.split('\n') if line.strip()]

    # NS
    ns_raw = dig("NS", domain)
    result["ns"] = [line.strip() for line in ns_raw.split('\n') if line.strip()]

    return result


# ── EXPOSED FILES CHECK ──────────────────────────────────────────

SENSITIVE_PATHS = [
    ("/.env",              "critical", "Environment file — may contain API keys and DB passwords"),
    ("/.git/config",       "critical", "Git config exposed — source code may be downloadable"),
    ("/.git/HEAD",         "critical", "Git repository exposed"),
    ("/wp-config.php",     "critical", "WordPress config — may expose database credentials"),
    ("/config.php",        "high",     "PHP config file exposed"),
    ("/.htaccess",         "medium",   "Apache config file exposed"),
    ("/robots.txt",        "low",      "Robots.txt (check for sensitive path disclosures)"),
    ("/sitemap.xml",       "info",     "Sitemap found"),
    ("/admin",             "medium",   "Admin panel exists"),
    ("/admin.php",         "high",     "PHP admin panel exists"),
    ("/phpmyadmin",        "high",     "phpMyAdmin panel exposed"),
    ("/backup.zip",        "critical", "Backup archive exposed"),
    ("/backup.sql",        "critical", "SQL backup exposed"),
    ("/.DS_Store",         "medium",   "macOS file index exposed — reveals directory structure"),
    ("/server-status",     "medium",   "Apache server-status page exposed"),
    ("/phpinfo.php",       "high",     "phpinfo() exposed — reveals server configuration"),
    ("/.well-known/security.txt", "info", "Security contact file (good practice)"),
]

def check_exposed_files(domain: str) -> list:
    base = f"https://{domain}"
    results = []
    for path, severity, desc in SENSITIVE_PATHS:
        try:
            req = urllib.request.Request(base + path,
                headers={"User-Agent": "Mozilla/5.0 SecurityScanner/1.0"})
            with urllib.request.urlopen(req, timeout=5) as r:
                if r.status == 200:
                    results.append({"path": path, "severity": severity,
                                    "description": desc, "status": 200,
                                    "url": base + path})
        except urllib.error.HTTPError as e:
            if e.code not in (403, 404, 410):
                results.append({"path": path, "severity": "info",
                                "description": f"Unexpected response: HTTP {e.code}",
                                "status": e.code, "url": base + path})
        except:
            pass
    return results


# ── TECH FINGERPRINT ─────────────────────────────────────────────

def fingerprint_tech(domain: str) -> dict:
    tech = {"server": None, "powered_by": None, "cms": None,
            "frameworks": [], "cdn": None, "waf": None}
    url = f"https://{domain}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as r:
            headers = dict(r.headers)
            body    = r.read(8192).decode("utf-8", errors="replace")
            tech["server"]     = headers.get("Server", headers.get("server"))
            tech["powered_by"] = headers.get("X-Powered-By", headers.get("x-powered-by"))
            # CMS detection
            if "wp-content" in body or "wp-json" in body:
                tech["cms"] = "WordPress"
            elif "Drupal" in body or "drupal" in headers.get("X-Generator",""):
                tech["cms"] = "Drupal"
            elif "Joomla" in body:
                tech["cms"] = "Joomla"
            elif "ghost-url" in body:
                tech["cms"] = "Ghost"
            # Frameworks
            if "React" in body or "__NEXT_DATA__" in body:
                tech["frameworks"].append("React/Next.js")
            if "ng-version" in body or "angular" in body.lower():
                tech["frameworks"].append("Angular")
            if "vue" in body.lower() and "data-v-" in body:
                tech["frameworks"].append("Vue.js")
            # CDN/WAF
            cf_header = headers.get("CF-RAY") or headers.get("cf-ray")
            if cf_header:
                tech["cdn"] = "Cloudflare"
                tech["waf"] = "Cloudflare WAF"
            elif headers.get("X-Cache") or headers.get("x-cache"):
                tech["cdn"] = "CDN detected"
            elif "fastly" in str(headers).lower():
                tech["cdn"] = "Fastly"
            elif "akamai" in str(headers).lower():
                tech["cdn"] = "Akamai"
    except Exception as e:
        tech["error"] = str(e)
    return tech


# ── PORT SCAN (web-relevant) ─────────────────────────────────────

def scan_web_ports(domain: str) -> list:
    try:
        ip = socket.gethostbyname(domain)
    except:
        return []
    web_ports = {
        80:   ("HTTP",     "medium",   "Unencrypted HTTP — redirect to HTTPS"),
        443:  ("HTTPS",    "low",      "HTTPS OK"),
        8080: ("HTTP-Alt", "high",     "Alternative HTTP port — often dev server"),
        8443: ("HTTPS-Alt","medium",   "Alternative HTTPS port"),
        8888: ("Jupyter",  "critical", "Jupyter Notebook — allows remote code execution"),
        3000: ("Node.js",  "high",     "Node.js dev server exposed to internet"),
        9200: ("Elastic",  "critical", "Elasticsearch — check auth enabled"),
        6379: ("Redis",    "critical", "Redis — check auth enabled"),
    }
    results = []
    for port, (svc, risk, detail) in web_ports.items():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.8)
            if s.connect_ex((ip, port)) == 0:
                results.append({"port": port, "service": svc, "risk": risk,
                                "detail": detail, "ip": ip})
            s.close()
        except:
            pass
    return results


# ── FULL WEBSITE SCAN ────────────────────────────────────────────

def website_scan(domain: str) -> dict:
    domain = domain.replace("https://","").replace("http://","").split("/")[0].strip()
    ssl_result     = check_ssl(domain)
    headers_result = check_http_headers(domain)
    dns_result     = check_dns_security(domain)
    exposed        = check_exposed_files(domain)
    tech           = fingerprint_tech(domain)
    ports          = scan_web_ports(domain)

    # Build issues list
    issues = []
    iid = 1

    # SSL issues
    if ssl_result.get("error"):
        issues.append({"id":iid,"severity":"critical","category":"SSL","title":"SSL certificate error","detail":ssl_result["error"],"cvss":9.0}); iid+=1
    elif ssl_result.get("expired"):
        issues.append({"id":iid,"severity":"critical","category":"SSL","title":"SSL certificate EXPIRED","detail":f"Certificate expired {abs(ssl_result['days_left'])} days ago","cvss":9.0}); iid+=1
    elif ssl_result.get("days_left") is not None and ssl_result["days_left"] < 30:
        issues.append({"id":iid,"severity":"high","category":"SSL","title":f"SSL certificate expires in {ssl_result['days_left']} days","detail":"Renew certificate immediately","cvss":7.0}); iid+=1
    if ssl_result.get("version") in ("TLSv1", "TLSv1.1"):
        issues.append({"id":iid,"severity":"high","category":"SSL","title":f"Weak TLS version: {ssl_result['version']}","detail":"TLS 1.0 and 1.1 are deprecated. Upgrade to TLS 1.2+","cvss":6.5}); iid+=1

    # Missing headers
    for h in headers_result.get("headers_missing", []):
        issues.append({"id":iid,"severity":h["severity"],"category":"Headers","title":f"Missing: {h['header']}","detail":h["desc"],"fix":h["recommendation"],"cvss":{"high":7.0,"medium":5.0,"low":3.0}.get(h["severity"],3.0)}); iid+=1

    # DNS issues
    for dns_issue in dns_result.get("issues", []):
        issues.append({"id":iid,"severity":dns_issue["severity"],"category":"DNS/Email","title":dns_issue["issue"],"detail":dns_issue["detail"],"fix":dns_issue.get("fix",""),"cvss":{"high":7.2,"medium":5.3,"low":3.0}.get(dns_issue["severity"],3.0)}); iid+=1

    # Exposed files
    for f in exposed:
        if f["severity"] != "info":
            issues.append({"id":iid,"severity":f["severity"],"category":"Exposure","title":f"Exposed: {f['path']}","detail":f["description"],"url":f["url"],"cvss":{"critical":9.5,"high":7.5,"medium":5.0}.get(f["severity"],3.0)}); iid+=1

    # Port issues
    for p in ports:
        if p["risk"] in ("critical","high"):
            issues.append({"id":iid,"severity":p["risk"],"category":"Network","title":f"Port {p['port']} ({p['service']}) open","detail":p["detail"],"cvss":{"critical":9.0,"high":7.0}.get(p["risk"],5.0)}); iid+=1

    # Score
    score = 100
    for issue in issues:
        if issue["severity"] == "critical": score -= 15
        elif issue["severity"] == "high":   score -= 8
        elif issue["severity"] == "medium": score -= 4
        elif issue["severity"] == "low":    score -= 1
    score = max(0, min(100, score))

    return {
        "timestamp": datetime.now().isoformat(),
        "scan_type": "website",
        "domain": domain,
        "hostname": domain,
        "ip": ports[0]["ip"] if ports else None,
        "ssl": ssl_result,
        "headers": headers_result,
        "dns": dns_result,
        "exposed_files": exposed,
        "tech": tech,
        "open_ports": ports,
        "issues": sorted(issues, key=lambda x: x["cvss"], reverse=True),
        "security_score": score,
    }
