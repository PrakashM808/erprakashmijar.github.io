"""
osint.py — OSINT & Threat Intelligence Engine
Email breach check, username enumeration, IP reputation,
domain intel, VirusTotal, AbuseIPDB, Shodan (free APIs)
"""
import socket
import re
import json
import urllib.request
import urllib.error
import urllib.parse
import os
import hashlib
from datetime import datetime
from typing import Optional


# ── HAVE I BEEN PWNED ────────────────────────────────────────────

def check_email_breaches(email: str) -> dict:
    """Check email against HIBP API v3 (requires API key — $3.50/month or use free k-anonymity for passwords)"""
    api_key = os.getenv("HIBP_API_KEY", "")
    result = {"email": email, "breached": False, "breach_count": 0,
              "breaches": [], "paste_count": 0, "error": None}
    if not api_key:
        result["error"] = "HIBP_API_KEY not configured. Get one at haveibeenpwned.com/API/Key"
        result["demo"] = True
        # Demo data to show the feature
        result["breached"] = True
        result["breach_count"] = 3
        result["breaches"] = [
            {"Name":"LinkedIn","BreachDate":"2016-05-05","DataClasses":["Email addresses","Passwords"],"Description":"LinkedIn breach — 164M accounts"},
            {"Name":"Adobe","BreachDate":"2013-10-04","DataClasses":["Email addresses","Password hints","Passwords"],"Description":"Adobe breach — 153M accounts"},
            {"Name":"Collection1","BreachDate":"2019-01-07","DataClasses":["Email addresses","Passwords"],"Description":"Collection #1 credential dump"},
        ]
        return result
    try:
        encoded = urllib.parse.quote(email)
        req = urllib.request.Request(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{encoded}?truncateResponse=false",
            headers={"hibp-api-key": api_key, "User-Agent": "PM-OFFSEC-Dashboard/3.0"}
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read())
            result["breached"]     = True
            result["breach_count"] = len(data)
            result["breaches"]     = data
    except urllib.error.HTTPError as e:
        if e.code == 404:
            result["breached"] = False
        elif e.code == 401:
            result["error"] = "Invalid HIBP API key"
        elif e.code == 429:
            result["error"] = "Rate limited — wait 1 minute"
        else:
            result["error"] = f"HTTP {e.code}"
    except Exception as e:
        result["error"] = str(e)

    # Also check pastes
    try:
        req2 = urllib.request.Request(
            f"https://haveibeenpwned.com/api/v3/pasteaccount/{urllib.parse.quote(email)}",
            headers={"hibp-api-key": api_key, "User-Agent": "PM-OFFSEC-Dashboard/3.0"}
        )
        with urllib.request.urlopen(req2, timeout=10) as r:
            pastes = json.loads(r.read())
            result["paste_count"] = len(pastes)
    except:
        pass
    return result


def check_password_pwned(password: str) -> dict:
    """Check if a password has been seen in breaches using k-anonymity (no API key needed)"""
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    result = {"pwned": False, "count": 0, "sha1_prefix": prefix}
    try:
        req = urllib.request.Request(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"User-Agent": "PM-OFFSEC-Dashboard/3.0"}
        )
        with urllib.request.urlopen(req, timeout=8) as r:
            body = r.read().decode()
            for line in body.split('\r\n'):
                if ':' in line:
                    h, count = line.split(':', 1)
                    if h == suffix:
                        result["pwned"] = True
                        result["count"] = int(count)
                        break
    except Exception as e:
        result["error"] = str(e)
    return result


# ── IP REPUTATION ────────────────────────────────────────────────

def check_ip_reputation(ip: str) -> dict:
    """Check IP against AbuseIPDB (free tier: 1000 checks/day)"""
    api_key = os.getenv("ABUSEIPDB_API_KEY", "")
    result = {"ip": ip, "abusive": False, "abuse_score": 0,
              "country": None, "isp": None, "reports": 0,
              "is_tor": False, "is_proxy": False, "error": None}
    if not api_key:
        result["error"] = "ABUSEIPDB_API_KEY not configured — get free key at abuseipdb.com"
        result["demo"]  = True
        # Demo for known bad IPs
        if ip.startswith("185."):
            result["abusive"] = True; result["abuse_score"] = 87
            result["country"] = "RU"; result["reports"] = 234
            result["isp"] = "Spamhaus Listed Network"
        return result
    try:
        params = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""})
        req = urllib.request.Request(
            f"https://api.abuseipdb.com/api/v2/check?{params}",
            headers={"Key": api_key, "Accept": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read())["data"]
            result["abusive"]    = data.get("abuseConfidenceScore", 0) > 25
            result["abuse_score"] = data.get("abuseConfidenceScore", 0)
            result["country"]    = data.get("countryCode")
            result["isp"]        = data.get("isp")
            result["reports"]    = data.get("totalReports", 0)
            result["is_tor"]     = data.get("isTor", False)
            result["is_proxy"]   = data.get("isPublicProxy", False)
            result["usage_type"] = data.get("usageType")
    except Exception as e:
        result["error"] = str(e)
    return result


def check_virustotal(target: str, target_type: str = "ip") -> dict:
    """Check URL/domain/IP/hash against VirusTotal (free: 4 lookups/minute)"""
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
    result = {"target": target, "type": target_type, "malicious": 0,
              "suspicious": 0, "harmless": 0, "total": 0, "error": None}
    if not api_key:
        result["error"] = "VIRUSTOTAL_API_KEY not configured — get free key at virustotal.com"
        return result
    try:
        endpoint_map = {
            "ip":     f"https://www.virustotal.com/api/v3/ip_addresses/{target}",
            "domain": f"https://www.virustotal.com/api/v3/domains/{target}",
            "url":    f"https://www.virustotal.com/api/v3/urls/{urllib.parse.quote_plus(target)}",
            "hash":   f"https://www.virustotal.com/api/v3/files/{target}",
        }
        url = endpoint_map.get(target_type, endpoint_map["domain"])
        req = urllib.request.Request(url, headers={"x-apikey": api_key})
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read())
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            result["malicious"]  = stats.get("malicious", 0)
            result["suspicious"] = stats.get("suspicious", 0)
            result["harmless"]   = stats.get("harmless", 0)
            result["undetected"] = stats.get("undetected", 0)
            result["total"]      = sum(stats.values())
            result["reputation"] = data.get("data",{}).get("attributes",{}).get("reputation", 0)
    except Exception as e:
        result["error"] = str(e)
    return result


# ── SHODAN LOOKUP ────────────────────────────────────────────────

def shodan_lookup(query: str) -> dict:
    """Lookup IP or domain in Shodan (free API: limited)"""
    api_key = os.getenv("SHODAN_API_KEY", "")
    result = {"query": query, "ports": [], "vulns": [], "tags": [],
              "org": None, "country": None, "error": None}
    if not api_key:
        result["error"] = "SHODAN_API_KEY not configured — get free key at shodan.io"
        return result
    try:
        # Resolve domain to IP if needed
        if not re.match(r'^\d+\.\d+\.\d+\.\d+$', query):
            try:
                query = socket.gethostbyname(query)
            except:
                result["error"] = f"Cannot resolve {query}"
                return result
        url = f"https://api.shodan.io/shodan/host/{query}?key={api_key}"
        req = urllib.request.Request(url, headers={"User-Agent": "PM-OFFSEC/3.0"})
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read())
            result["ports"]   = data.get("ports", [])
            result["vulns"]   = list(data.get("vulns", {}).keys())
            result["tags"]    = data.get("tags", [])
            result["org"]     = data.get("org")
            result["country"] = data.get("country_name")
            result["hostnames"] = data.get("hostnames", [])
            result["os"]      = data.get("os")
            result["ip"]      = query
    except urllib.error.HTTPError as e:
        if e.code == 404:
            result["error"] = "IP not found in Shodan database"
        else:
            result["error"] = f"Shodan API error: HTTP {e.code}"
    except Exception as e:
        result["error"] = str(e)
    return result


# ── USERNAME LOOKUP ──────────────────────────────────────────────

USERNAME_PLATFORMS = [
    ("GitHub",      "https://github.com/{}",              "Not Found"),
    ("Twitter/X",   "https://x.com/{}",                   "doesn't exist"),
    ("Instagram",   "https://www.instagram.com/{}/",      "Sorry, this page"),
    ("Reddit",      "https://www.reddit.com/user/{}/",    "Sorry, nobody"),
    ("LinkedIn",    "https://www.linkedin.com/in/{}/",    "Page not found"),
    ("HackerOne",   "https://hackerone.com/{}",           "404"),
    ("Bugcrowd",    "https://bugcrowd.com/{}",            "404"),
    ("TryHackMe",   "https://tryhackme.com/p/{}",         "404"),
    ("HackTheBox",  "https://app.hackthebox.com/users/{}", "404"),
    ("Medium",      "https://medium.com/@{}",             "404"),
    ("Dev.to",      "https://dev.to/{}",                  "404"),
    ("GitLab",      "https://gitlab.com/{}",              "404"),
]

def lookup_username(username: str) -> list:
    """Check if a username exists across platforms"""
    results = []
    for platform, url_template, not_found_indicator in USERNAME_PLATFORMS:
        url = url_template.format(username)
        entry = {"platform": platform, "url": url, "found": False, "username": username}
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=6) as r:
                body = r.read(4096).decode("utf-8", errors="replace")
                entry["found"] = r.status == 200 and not_found_indicator.lower() not in body.lower()
        except urllib.error.HTTPError as e:
            entry["found"] = e.code == 200
        except:
            entry["error"] = "timeout"
        results.append(entry)
    return results


# ── DOMAIN INTEL ────────────────────────────────────────────────

def domain_intel(domain: str) -> dict:
    """Comprehensive domain intelligence gathering"""
    domain = domain.replace("https://","").replace("http://","").split("/")[0].strip()
    result = {
        "domain": domain,
        "timestamp": datetime.now().isoformat(),
        "dns": check_dns_security(domain),
        "ssl": check_ssl(domain),
        "virustotal": check_virustotal(domain, "domain"),
        "whois_hint": f"Run: whois {domain}",
    }
    # Try to get IP for reputation check
    try:
        ip = socket.gethostbyname(domain)
        result["ip"] = ip
        result["ip_reputation"] = check_ip_reputation(ip)
        result["shodan"] = shodan_lookup(ip)
    except:
        result["ip"] = None
    return result


# ── FULL OSINT REPORT ────────────────────────────────────────────

def full_email_osint(email: str) -> dict:
    """Complete OSINT report for an email address"""
    domain = email.split("@")[-1] if "@" in email else ""
    username = email.split("@")[0] if "@" in email else email
    return {
        "target": email,
        "type": "email",
        "timestamp": datetime.now().isoformat(),
        "breach_check": check_email_breaches(email),
        "username_check": lookup_username(username),
        "domain_intel": domain_intel(domain) if domain else None,
    }
