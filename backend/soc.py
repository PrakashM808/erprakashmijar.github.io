"""
soc.py — SOC Analyst Platform
Incident management, IOC database, MITRE ATT&CK mapping,
Wazuh integration, log analysis, threat detection
"""
import os
import json
import re
import uuid
from datetime import datetime
from typing import Optional
import urllib.request
import urllib.parse


# ── MITRE ATT&CK MAPPING ─────────────────────────────────────────

MITRE_TECHNIQUES = {
    # Initial Access
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access",   "color": "#ff3b5c"},
    "T1133": {"name": "External Remote Services",          "tactic": "Initial Access",   "color": "#ff3b5c"},
    "T1566": {"name": "Phishing",                          "tactic": "Initial Access",   "color": "#ff3b5c"},
    "T1078": {"name": "Valid Accounts",                    "tactic": "Initial Access",   "color": "#ff3b5c"},
    # Execution
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution",        "color": "#ff8c42"},
    "T1053": {"name": "Scheduled Task/Job",                "tactic": "Execution",        "color": "#ff8c42"},
    # Persistence
    "T1098": {"name": "Account Manipulation",              "tactic": "Persistence",      "color": "#f5c842"},
    "T1543": {"name": "Create/Modify System Process",      "tactic": "Persistence",      "color": "#f5c842"},
    "T1136": {"name": "Create Account",                    "tactic": "Persistence",      "color": "#f5c842"},
    # Privilege Escalation
    "T1548": {"name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation", "color": "#a855f7"},
    "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation", "color": "#a855f7"},
    # Defense Evasion
    "T1562": {"name": "Impair Defenses",                   "tactic": "Defense Evasion",  "color": "#3b82f6"},
    "T1070": {"name": "Indicator Removal",                 "tactic": "Defense Evasion",  "color": "#3b82f6"},
    "T1036": {"name": "Masquerading",                      "tactic": "Defense Evasion",  "color": "#3b82f6"},
    # Credential Access
    "T1110": {"name": "Brute Force",                       "tactic": "Credential Access","color": "#ec4899"},
    "T1003": {"name": "OS Credential Dumping",             "tactic": "Credential Access","color": "#ec4899"},
    "T1552": {"name": "Unsecured Credentials",             "tactic": "Credential Access","color": "#ec4899"},
    # Discovery
    "T1046": {"name": "Network Service Discovery",         "tactic": "Discovery",        "color": "#10b981"},
    "T1082": {"name": "System Information Discovery",      "tactic": "Discovery",        "color": "#10b981"},
    "T1083": {"name": "File and Directory Discovery",      "tactic": "Discovery",        "color": "#10b981"},
    # Lateral Movement
    "T1021": {"name": "Remote Services",                   "tactic": "Lateral Movement", "color": "#f59e0b"},
    "T1091": {"name": "Replication Through Removable Media","tactic": "Lateral Movement","color": "#f59e0b"},
    # Collection
    "T1005": {"name": "Data from Local System",            "tactic": "Collection",       "color": "#00d4ff"},
    "T1074": {"name": "Data Staged",                       "tactic": "Collection",       "color": "#00d4ff"},
    # Exfiltration
    "T1048": {"name": "Exfiltration Over Alt Protocol",    "tactic": "Exfiltration",     "color": "#7b2fff"},
    "T1041": {"name": "Exfiltration Over C2 Channel",      "tactic": "Exfiltration",     "color": "#7b2fff"},
    # Impact
    "T1486": {"name": "Data Encrypted for Impact",         "tactic": "Impact",           "color": "#ff3b5c"},
    "T1490": {"name": "Inhibit System Recovery",           "tactic": "Impact",           "color": "#ff3b5c"},
    "T1489": {"name": "Service Stop",                      "tactic": "Impact",           "color": "#ff3b5c"},
}

# Map scan findings to MITRE techniques
FINDING_TO_MITRE = {
    "ssh root login":          ["T1078", "T1133"],
    "brute force":             ["T1110"],
    "failed password":         ["T1110"],
    "port scan":               ["T1046"],
    "firewall inactive":       ["T1562"],
    "cron":                    ["T1053"],
    "redis":                   ["T1552"],
    "mysql exposed":           ["T1190"],
    "exposed":                 ["T1190"],
    "privilege escalation":    ["T1068", "T1548"],
    "lateral movement":        ["T1021"],
    "reverse shell":           ["T1059"],
    "persistence":             ["T1543"],
    "credential":              ["T1552", "T1003"],
    "exfiltration":            ["T1048"],
    "encryption":              ["T1486"],
    "log":                     ["T1070"],
}

def map_to_mitre(findings: list) -> list:
    """Map scan findings to MITRE ATT&CK techniques"""
    mapped = {}
    for finding in findings:
        title = finding.get("title", "").lower()
        for keyword, techniques in FINDING_TO_MITRE.items():
            if keyword in title:
                for tech_id in techniques:
                    if tech_id in MITRE_TECHNIQUES:
                        tech = MITRE_TECHNIQUES[tech_id].copy()
                        tech["technique_id"] = tech_id
                        tech["triggered_by"]  = finding.get("title")
                        tech["url"] = f"https://attack.mitre.org/techniques/{tech_id}/"
                        mapped[tech_id] = tech
    return list(mapped.values())


# ── IN-MEMORY STORES ─────────────────────────────────────────────
# (replace with PostgreSQL/SQLite for production)

_incidents: dict = {}   # incident_id -> incident
_iocs:      dict = {}   # ioc_id -> ioc
_playbooks: dict = {}   # playbook_id -> playbook
_soc_log:   list = []   # audit log


# ── INCIDENTS ────────────────────────────────────────────────────

INCIDENT_STATUSES  = ["open", "investigating", "contained", "resolved", "closed"]
INCIDENT_SEVERITIES = ["critical", "high", "medium", "low", "informational"]

def create_incident(title: str, description: str, severity: str,
                    source: str, created_by: str,
                    affected_devices: list = None,
                    mitre_techniques: list = None) -> dict:
    iid = str(uuid.uuid4())[:8].upper()
    now = datetime.now().isoformat()
    incident = {
        "id": iid,
        "title": title,
        "description": description,
        "severity": severity,
        "status": "open",
        "source": source,
        "created_by": created_by,
        "created_at": now,
        "updated_at": now,
        "resolved_at": None,
        "assigned_to": None,
        "affected_devices": affected_devices or [],
        "mitre_techniques": mitre_techniques or [],
        "timeline": [{"time": now, "action": "Incident created", "user": created_by, "note": description}],
        "iocs": [],
        "tags": [],
        "mttd": None,  # Mean time to detect
        "mttr": None,  # Mean time to resolve
    }
    _incidents[iid] = incident
    _soc_log.append({"time": now, "event": f"Incident {iid} created: {title}", "user": created_by})
    return incident

def update_incident(iid: str, updates: dict, updated_by: str) -> dict:
    if iid not in _incidents:
        return None
    inc = _incidents[iid]
    now = datetime.now().isoformat()
    old_status = inc.get("status")
    for k, v in updates.items():
        if k not in ("id", "created_at", "timeline"):
            inc[k] = v
    inc["updated_at"] = now
    if updates.get("status") and updates["status"] != old_status:
        inc["timeline"].append({"time": now, "action": f"Status changed: {old_status} → {updates['status']}",
                                "user": updated_by})
        if updates["status"] == "resolved":
            inc["resolved_at"] = now
            # Calculate MTTR
            created = datetime.fromisoformat(inc["created_at"])
            resolved = datetime.fromisoformat(now)
            inc["mttr"] = int((resolved - created).total_seconds() / 60)  # minutes
    if updates.get("note"):
        inc["timeline"].append({"time": now, "action": "Note added", "user": updated_by, "note": updates["note"]})
    _soc_log.append({"time": now, "event": f"Incident {iid} updated by {updated_by}", "user": updated_by})
    return inc

def get_incidents(status: str = None, severity: str = None) -> list:
    incidents = list(_incidents.values())
    if status:
        incidents = [i for i in incidents if i["status"] == status]
    if severity:
        incidents = [i for i in incidents if i["severity"] == severity]
    return sorted(incidents, key=lambda x: x["created_at"], reverse=True)

def get_incident(iid: str) -> dict:
    return _incidents.get(iid)

def auto_create_incident_from_scan(scan_data: dict, created_by: str = "system") -> list:
    """Automatically create incidents from scan findings"""
    created = []
    critical_issues = [i for i in scan_data.get("issues", []) if i["severity"] == "critical"]
    if critical_issues:
        mitre = map_to_mitre(critical_issues)
        inc = create_incident(
            title=f"Critical vulnerabilities on {scan_data.get('hostname', 'unknown')}",
            description=f"Automated scan found {len(critical_issues)} critical issues. Top: {critical_issues[0]['title']}",
            severity="critical",
            source="automated_scan",
            created_by=created_by,
            affected_devices=[scan_data.get("ip", scan_data.get("hostname"))],
            mitre_techniques=[t["technique_id"] for t in mitre]
        )
        created.append(inc)
    return created


# ── IOC DATABASE ─────────────────────────────────────────────────

IOC_TYPES = ["ip", "domain", "url", "hash", "email", "filename", "registry_key", "user_agent"]

def add_ioc(ioc_type: str, value: str, severity: str, description: str,
            source: str, added_by: str, tags: list = None) -> dict:
    iid = str(uuid.uuid4())[:8]
    now = datetime.now().isoformat()
    ioc = {
        "id": iid, "type": ioc_type, "value": value,
        "severity": severity, "description": description,
        "source": source, "added_by": added_by,
        "created_at": now, "last_seen": now,
        "hit_count": 0, "tags": tags or [],
        "active": True,
        "related_incidents": [],
    }
    _iocs[iid] = ioc
    _soc_log.append({"time": now, "event": f"IOC added: {ioc_type}/{value}", "user": added_by})
    return ioc

def search_iocs(query: str = None, ioc_type: str = None) -> list:
    iocs = list(_iocs.values())
    if query:
        q = query.lower()
        iocs = [i for i in iocs if q in i["value"].lower() or q in i.get("description","").lower()]
    if ioc_type:
        iocs = [i for i in iocs if i["type"] == ioc_type]
    return sorted(iocs, key=lambda x: x["created_at"], reverse=True)

def check_ioc_match(value: str) -> list:
    """Check if a value matches any known IOC"""
    matches = []
    for ioc in _iocs.values():
        if ioc["active"] and (ioc["value"] == value or value in ioc["value"] or ioc["value"] in value):
            ioc["hit_count"] += 1
            ioc["last_seen"]  = datetime.now().isoformat()
            matches.append(ioc)
    return matches

def extract_iocs_from_scan(scan_data: dict, added_by: str = "system") -> list:
    """Auto-extract IOCs from scan data"""
    added = []
    # Failed login IPs
    fl = scan_data.get("failed_logins", {})
    if fl.get("top_ip") and fl["top_ip"] != "none":
        ioc = add_ioc("ip", fl["top_ip"], "high",
                      f"Top attacker IP — {fl.get('last_24h',0)} failed login attempts",
                      f"scan:{scan_data.get('hostname')}", added_by, tags=["brute-force"])
        added.append(ioc)
    return added


# ── WAZUH INTEGRATION ────────────────────────────────────────────

def get_wazuh_alerts(limit: int = 50, level: int = None) -> dict:
    """Fetch alerts from Wazuh REST API"""
    wazuh_url  = os.getenv("WAZUH_URL", "https://localhost:55000")
    wazuh_user = os.getenv("WAZUH_USER", "wazuh")
    wazuh_pass = os.getenv("WAZUH_PASSWORD", "")
    result = {"alerts": [], "total": 0, "error": None, "connected": False}
    if not wazuh_pass:
        result["error"] = "WAZUH_URL/WAZUH_USER/WAZUH_PASSWORD not configured in .env"
        result["demo"]  = True
        result["alerts"] = _demo_wazuh_alerts()
        result["total"]  = len(result["alerts"])
        return result
    import base64
    try:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        token_req = urllib.request.Request(
            f"{wazuh_url}/security/user/authenticate",
            headers={"Authorization": "Basic " + base64.b64encode(f"{wazuh_user}:{wazuh_pass}".encode()).decode()}
        )
        with urllib.request.urlopen(token_req, context=ctx, timeout=8) as r:
            token = json.loads(r.read())["data"]["token"]
        params = f"?limit={limit}" + (f"&level={level}" if level else "")
        alerts_req = urllib.request.Request(
            f"{wazuh_url}/alerts{params}",
            headers={"Authorization": f"Bearer {token}"}
        )
        with urllib.request.urlopen(alerts_req, context=ctx, timeout=10) as r:
            data = json.loads(r.read())
            result["alerts"]    = data.get("data", {}).get("affected_items", [])
            result["total"]     = data.get("data", {}).get("total_affected_items", 0)
            result["connected"] = True
    except Exception as e:
        result["error"] = str(e)
        result["demo"]  = True
        result["alerts"] = _demo_wazuh_alerts()
    return result

def get_wazuh_agents() -> dict:
    """Get list of Wazuh agents"""
    wazuh_url  = os.getenv("WAZUH_URL", "")
    if not wazuh_url:
        return {"agents": _demo_wazuh_agents(), "demo": True}
    # Same auth flow as above — simplified
    return {"agents": _demo_wazuh_agents(), "demo": True, "note": "Connect Wazuh to see live agents"}

def _demo_wazuh_alerts() -> list:
    now = datetime.now().isoformat()
    return [
        {"id":"1","timestamp":now,"rule":{"id":"5503","description":"User login failed","level":5,"groups":["authentication_failed"]},"agent":{"id":"001","name":"prod-server-01","ip":"192.168.1.100"},"data":{"srcip":"185.224.128.42","dstuser":"root"},"mitre":{"technique":["T1110"]}},
        {"id":"2","timestamp":now,"rule":{"id":"0002","description":"New file in /etc directory","level":7,"groups":["syscheck"]},"agent":{"id":"001","name":"prod-server-01","ip":"192.168.1.100"},"data":{},"mitre":{"technique":["T1543"]}},
        {"id":"3","timestamp":now,"rule":{"id":"0003","description":"Possible port scan from external IP","level":8,"groups":["scan"]},"agent":{"id":"002","name":"web-server-01","ip":"192.168.1.101"},"data":{"srcip":"45.33.32.156"},"mitre":{"technique":["T1046"]}},
        {"id":"4","timestamp":now,"rule":{"id":"0004","description":"Rootkit detected — suspicious process","level":12,"groups":["rootcheck"]},"agent":{"id":"001","name":"prod-server-01","ip":"192.168.1.100"},"data":{},"mitre":{"technique":["T1543","T1562"]}},
        {"id":"5","timestamp":now,"rule":{"id":"0005","description":"Multiple authentication failures","level":10,"groups":["authentication_failures"]},"agent":{"id":"003","name":"db-server-01","ip":"192.168.1.102"},"data":{"srcip":"103.35.74.45","dstuser":"admin"},"mitre":{"technique":["T1110"]}},
    ]

def _demo_wazuh_agents() -> list:
    return [
        {"id":"001","name":"prod-server-01","ip":"192.168.1.100","status":"active","version":"v4.7.2","os":{"platform":"ubuntu","version":"22.04"}},
        {"id":"002","name":"web-server-01","ip":"192.168.1.101","status":"active","version":"v4.7.2","os":{"platform":"ubuntu","version":"20.04"}},
        {"id":"003","name":"db-server-01","ip":"192.168.1.102","status":"disconnected","version":"v4.7.1","os":{"platform":"centos","version":"8"}},
    ]


# ── SPLUNK INTEGRATION ────────────────────────────────────────────

def splunk_search(query: str, earliest: str = "-24h", latest: str = "now") -> dict:
    """Run a Splunk search (requires Splunk HEC configured)"""
    splunk_url   = os.getenv("SPLUNK_URL", "")
    splunk_token = os.getenv("SPLUNK_TOKEN", "")
    result = {"results": [], "total": 0, "error": None, "connected": False}
    if not all([splunk_url, splunk_token]):
        result["error"] = "SPLUNK_URL and SPLUNK_TOKEN not configured in .env"
        result["demo"]  = True
        result["results"] = _demo_splunk_results(query)
        return result
    try:
        import base64
        search_body = urllib.parse.urlencode({
            "search": f"search {query}", "earliest_time": earliest, "latest_time": latest,
            "output_mode": "json", "count": 50
        }).encode()
        req = urllib.request.Request(
            f"{splunk_url}/services/search/jobs/export",
            data=search_body,
            headers={"Authorization": f"Bearer {splunk_token}", "Content-Type": "application/x-www-form-urlencoded"}
        )
        with urllib.request.urlopen(req, timeout=15) as r:
            raw = r.read().decode()
            for line in raw.strip().split('\n'):
                if line:
                    try:
                        result["results"].append(json.loads(line))
                    except:
                        pass
            result["total"]     = len(result["results"])
            result["connected"] = True
    except Exception as e:
        result["error"] = str(e)
        result["demo"]  = True
        result["results"] = _demo_splunk_results(query)
    return result

def splunk_send_log(event: dict) -> dict:
    """Send a log event to Splunk via HEC"""
    splunk_hec_url   = os.getenv("SPLUNK_HEC_URL", "")
    splunk_hec_token = os.getenv("SPLUNK_HEC_TOKEN", "")
    if not all([splunk_hec_url, splunk_hec_token]):
        return {"ok": False, "error": "SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN not configured"}
    try:
        payload = json.dumps({"event": event, "sourcetype": "pm_offsec", "source": "security_dashboard"}).encode()
        req = urllib.request.Request(
            splunk_hec_url,
            data=payload,
            headers={"Authorization": f"Splunk {splunk_hec_token}", "Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=8) as r:
            return {"ok": True, "response": json.loads(r.read())}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def _demo_splunk_results(query: str) -> list:
    return [
        {"_time": datetime.now().isoformat(), "host": "prod-server-01", "source": "/var/log/auth.log", "_raw": "Failed password for root from 185.224.128.42 port 54321 ssh2"},
        {"_time": datetime.now().isoformat(), "host": "web-server-01",  "source": "/var/log/nginx/access.log", "_raw": '192.168.1.1 - - [GET /admin HTTP/1.1] 404 0'},
        {"_time": datetime.now().isoformat(), "host": "prod-server-01", "source": "/var/log/syslog", "_raw": "UFW BLOCK: IN=eth0 SRC=103.35.74.45 DST=x.x.x.x PROTO=TCP DPT=3306"},
    ]


# ── SOC METRICS ──────────────────────────────────────────────────

def get_soc_metrics() -> dict:
    incidents = list(_incidents.values())
    open_inc  = [i for i in incidents if i["status"] in ("open","investigating")]
    resolved  = [i for i in incidents if i["status"] in ("resolved","closed") and i.get("mttr")]
    avg_mttr  = round(sum(i["mttr"] for i in resolved) / len(resolved)) if resolved else 0
    by_sev = {}
    for s in INCIDENT_SEVERITIES:
        by_sev[s] = len([i for i in incidents if i["severity"]==s])
    return {
        "total_incidents":  len(incidents),
        "open_incidents":   len(open_inc),
        "resolved_incidents": len([i for i in incidents if i["status"]=="resolved"]),
        "avg_mttr_minutes": avg_mttr,
        "by_severity":      by_sev,
        "total_iocs":       len(_iocs),
        "active_iocs":      len([i for i in _iocs.values() if i["active"]]),
        "soc_log_entries":  len(_soc_log),
    }


# ── DEFAULT PLAYBOOKS ─────────────────────────────────────────────

DEFAULT_PLAYBOOKS = [
    {
        "id": "pb-001", "name": "SSH Brute Force Response",
        "trigger": "Multiple failed SSH login attempts",
        "severity": "high",
        "steps": [
            "1. Identify source IP from /var/log/auth.log",
            "2. Block IP: sudo ufw deny from <IP> to any",
            "3. Check if any login succeeded: grep 'Accepted' /var/log/auth.log",
            "4. If compromised: isolate machine, preserve logs",
            "5. Enable fail2ban: sudo apt install fail2ban",
            "6. Review and harden SSH config: disable root login, use key auth",
            "7. Document incident and close ticket",
        ],
        "commands": [
            "grep 'Failed password' /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn",
            "sudo ufw deny from ATTACKER_IP to any",
            "sudo fail2ban-client status sshd",
        ],
        "mitre": ["T1110"],
    },
    {
        "id": "pb-002", "name": "Exposed Database Response",
        "trigger": "Database port (3306/5432/6379) exposed to internet",
        "severity": "critical",
        "steps": [
            "1. Immediately block port at firewall: sudo ufw deny 3306",
            "2. Check active connections: sudo ss -tnp | grep 3306",
            "3. Review database access logs for unauthorized queries",
            "4. Change database passwords immediately",
            "5. Bind database to localhost: bind-address = 127.0.0.1 in my.cnf",
            "6. Enable database audit logging",
            "7. Check for data exfiltration signs in network logs",
            "8. Create incident report with timeline",
        ],
        "commands": [
            "sudo ufw deny 3306",
            "sudo ss -tnp | grep 3306",
            "sudo grep -i 'error\\|warning\\|access denied' /var/log/mysql/error.log | tail -50",
        ],
        "mitre": ["T1190", "T1048"],
    },
    {
        "id": "pb-003", "name": "Malware Detection Response",
        "trigger": "Suspicious process or rootkit detected",
        "severity": "critical",
        "steps": [
            "1. DO NOT REBOOT — preserve volatile memory",
            "2. Isolate machine from network if possible",
            "3. Capture running processes: ps aux > /tmp/processes.txt",
            "4. Capture network connections: ss -tnp > /tmp/connections.txt",
            "5. Run rkhunter/chkrootkit scan",
            "6. Check for modified system files: debsums -c 2>/dev/null",
            "7. Take memory dump if possible",
            "8. Preserve logs before any changes",
            "9. Rebuild from clean backup if compromise confirmed",
        ],
        "commands": [
            "ps aux | sort -k3 -rn | head -20",
            "sudo rkhunter --check --skip-keypress",
            "sudo chkrootkit",
            "find /tmp /var/tmp -name '*.sh' -o -name '*.py' 2>/dev/null",
        ],
        "mitre": ["T1543", "T1562", "T1070"],
    },
    {
        "id": "pb-004", "name": "Privilege Escalation Response",
        "trigger": "Unauthorized privilege escalation detected",
        "severity": "critical",
        "steps": [
            "1. Identify which user escalated and when",
            "2. Review sudo log: sudo cat /var/log/auth.log | grep sudo",
            "3. Check for SUID binaries modified recently",
            "4. Review /etc/sudoers for unauthorized entries",
            "5. Check for new user accounts: cat /etc/passwd",
            "6. Disable compromised account: sudo usermod -L username",
            "7. Reset all privileged account passwords",
            "8. Audit cron jobs: crontab -l -u root",
        ],
        "commands": [
            "grep sudo /var/log/auth.log | tail -50",
            "find / -perm /4000 -newer /etc/passwd 2>/dev/null",
            "cat /etc/sudoers | grep -v '^#' | grep -v '^$'",
            "awk -F: '$3==0' /etc/passwd",
        ],
        "mitre": ["T1068", "T1548", "T1136"],
    },
]

def get_playbooks() -> list:
    return DEFAULT_PLAYBOOKS + list(_playbooks.values())

def get_playbook(pid: str) -> dict:
    built_in = {p["id"]: p for p in DEFAULT_PLAYBOOKS}
    return built_in.get(pid) or _playbooks.get(pid)
