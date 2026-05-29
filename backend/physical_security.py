"""
physical_security.py — ATM & Vending Machine Security Scanner
Covers network-reachable checks for physical security devices.
Physical inspection checks are assessment-based (no SSH needed).
"""
import os, asyncio, socket, httpx
from datetime import datetime
from typing import List, Optional

# ── ATM Network Security Checks ─────────────────────────────────
async def scan_atm_network(ip: str, port_range: list = None) -> dict:
    """Scan ATM for network-level security issues"""
    if not ip:
        return {"error": "No IP provided", "checks": []}

    findings = []
    ports_to_check = port_range or [
        3389,   # RDP — CRITICAL if open
        22,     # SSH — should be blocked externally
        23,     # Telnet — CRITICAL if open
        80,     # HTTP management
        443,    # HTTPS management
        8080,   # Alt HTTP
        4000,   # XFS/ATM service common port
        9000,   # Management console
        5900,   # VNC — CRITICAL if open
    ]

    open_ports = []
    for port in ports_to_check:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.5)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                open_ports.append(port)
        except Exception:
            pass

    # Evaluate findings
    critical_ports = {3389: "RDP", 5900: "VNC", 23: "Telnet"}
    for port in open_ports:
        if port in critical_ports:
            findings.append({
                "check": "open_port_critical",
                "port": port,
                "service": critical_ports[port],
                "severity": "critical",
                "title": f"{critical_ports[port]} Port Open ({port})",
                "description": f"{critical_ports[port]} is accessible from the network. This is a primary jackpotting attack vector.",
                "remediation": f"Immediately close port {port}. Disable {critical_ports[port]} on the ATM. Use VPN-only remote access."
            })
        elif port == 22:
            findings.append({
                "check": "ssh_exposed",
                "port": 22,
                "service": "SSH",
                "severity": "high",
                "title": "SSH Port Exposed",
                "description": "SSH is accessible. Ensure key-only authentication and limit to management IPs only.",
                "remediation": "Restrict SSH to management IP range only via firewall. Enable key-based auth. Disable password auth."
            })
        elif port in [80, 8080]:
            findings.append({
                "check": "http_management",
                "port": port,
                "service": "HTTP",
                "severity": "high",
                "title": f"Unencrypted Management Interface ({port})",
                "description": "HTTP management interface exposes credentials in plaintext.",
                "remediation": f"Disable HTTP on port {port}. Use HTTPS only. Add client certificate authentication."
            })

    # Calculate network score
    score = 100
    for f in findings:
        if f["severity"] == "critical": score -= 30
        elif f["severity"] == "high": score -= 15
        elif f["severity"] == "medium": score -= 8
    score = max(0, score)

    return {
        "ip": ip,
        "open_ports": open_ports,
        "findings": findings,
        "network_score": score,
        "critical_count": sum(1 for f in findings if f["severity"] == "critical"),
        "scanned_at": datetime.utcnow().isoformat()
    }

async def scan_vending_network(ip: str) -> dict:
    """Scan vending machine for IoT network vulnerabilities"""
    if not ip:
        return {"error": "No IP provided", "checks": []}

    findings = []
    # Common vending machine / IoT ports
    ports_to_check = [
        80, 443, 8080, 8443,  # Web interfaces
        1883,                  # MQTT (unencrypted IoT protocol) — CRITICAL
        8883,                  # MQTT over TLS (acceptable)
        5683,                  # CoAP (IoT protocol)
        161,                   # SNMP — info leak
        23,                    # Telnet — CRITICAL
        22,                    # SSH
        9100,                  # Raw printing / POS
        6379,                  # Redis (exposed) — CRITICAL
        27017,                 # MongoDB exposed — CRITICAL
    ]

    open_ports = []
    for port in ports_to_check:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.5)
            if sock.connect_ex((ip, port)) == 0:
                open_ports.append(port)
            sock.close()
        except Exception:
            pass

    critical_iot = {
        1883: ("MQTT Unencrypted", "IoT message broker with no encryption. All device commands visible in plaintext."),
        6379: ("Redis Exposed", "Database exposed without authentication. Full data access possible."),
        27017: ("MongoDB Exposed", "Database accessible without credentials. Critical data exposure."),
        23: ("Telnet Open", "Unencrypted remote access protocol. Credentials sent in plaintext."),
    }

    for port in open_ports:
        if port in critical_iot:
            name, desc = critical_iot[port]
            findings.append({
                "port": port, "service": name, "severity": "critical",
                "title": f"{name} (port {port})",
                "description": desc,
                "remediation": f"Immediately close port {port}. " + (
                    "Use MQTT over TLS (port 8883) with authentication." if port == 1883 else
                    "Bind to localhost only. Add authentication." if port in [6379, 27017] else
                    "Disable Telnet. Use SSH with key auth."
                )
            })
        elif port == 161:
            findings.append({
                "port": 161, "service": "SNMP", "severity": "medium",
                "title": "SNMP Accessible",
                "description": "SNMP can expose device configuration, network topology, and credentials.",
                "remediation": "Disable SNMPv1/v2c. Use SNMPv3 with authentication and encryption. Restrict to management IPs."
            })

    # Check for default web credentials
    default_cred_check = {"passed": True, "tested": False}
    if 80 in open_ports or 8080 in open_ports:
        port = 80 if 80 in open_ports else 8080
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                r = await client.get(f"http://{ip}:{port}", follow_redirects=True)
                if r.status_code == 200 and ("login" in r.text.lower() or "admin" in r.text.lower()):
                    default_cred_check["tested"] = True
                    # Check for common default logins
                    for user, pw in [("admin","admin"), ("admin","password"), ("root","root"), ("admin","1234")]:
                        try:
                            r2 = await client.post(f"http://{ip}:{port}/login",
                                                   data={"username":user,"password":pw}, timeout=3)
                            if r2.status_code == 200 and "logout" in r2.text.lower():
                                default_cred_check["passed"] = False
                                findings.append({
                                    "port": port, "service": "Web Auth",
                                    "severity": "critical",
                                    "title": "Default Credentials Active",
                                    "description": f"Default credentials ({user}/{pw}) accepted on management interface.",
                                    "remediation": "Change default credentials immediately. Enable MFA on management interface."
                                })
                                break
                        except Exception:
                            pass
        except Exception:
            pass

    score = 100
    for f in findings:
        score -= 30 if f["severity"] == "critical" else 15 if f["severity"] == "high" else 8
    score = max(0, score)

    return {
        "ip": ip,
        "open_ports": open_ports,
        "findings": findings,
        "network_score": score,
        "critical_count": sum(1 for f in findings if f["severity"] == "critical"),
        "default_creds_tested": default_cred_check["tested"],
        "scanned_at": datetime.utcnow().isoformat()
    }

def get_atm_compliance_summary(os_type: str, network_type: str, manufacturer: str) -> dict:
    """Generate compliance posture based on known config"""
    issues = []
    score  = 100

    # OS risk
    if "XP" in os_type:
        issues.append({"severity":"critical","issue":"Windows XP is end-of-life (2014). No security patches.",
                       "standard":"PCI DSS 6.3.3, CIS Control 2"})
        score -= 35
    elif "7" in os_type:
        issues.append({"severity":"critical","issue":"Windows 7 is end-of-life (2020). Requires ESU for patches.",
                       "standard":"PCI DSS 6.3.3"})
        score -= 25

    # Network risk
    if network_type == "public_internet":
        issues.append({"severity":"critical","issue":"ATM on public internet increases jackpotting risk significantly.",
                       "standard":"PCI DSS 1.3.1"})
        score -= 20

    # General compliance gaps
    compliance_items = [
        {"id":"PCI-6.1","title":"Latest security patches applied","status":"unknown"},
        {"id":"PCI-8.3","title":"MFA for all remote access","status":"unknown"},
        {"id":"PCI-7.1","title":"Least privilege access control","status":"unknown"},
        {"id":"PCI-10.1","title":"Audit logging enabled","status":"unknown"},
        {"id":"PCI-11.3","title":"Penetration testing performed","status":"unknown"},
        {"id":"CIS-4.1","title":"Application whitelisting active","status":"unknown"},
    ]

    return {
        "os": os_type, "network": network_type, "manufacturer": manufacturer,
        "compliance_score": max(0, score),
        "issues": issues,
        "compliance_items": compliance_items,
        "pci_dss_applicable": True,
        "recommendations": [
            "Migrate to Windows 10 IoT or Linux-based ATM OS",
            "Implement network segmentation — ATMs on dedicated VLAN",
            "Enable application whitelisting (AppLocker)",
            "Deploy ATM-specific security software (Trend Micro Safe Lock)",
            "Conduct annual physical security audit per FS-ISAC guidelines",
        ]
    }


# ── IP Camera / NVR / DVR Security Scanner ──────────────────────
# Common ports used by IP cameras, NVRs and DVRs across vendors.
CAMERA_PORTS = {
    80:    "HTTP web interface",
    443:   "HTTPS web interface",
    554:   "RTSP video stream",
    8000:  "Hikvision SDK / web",
    8080:  "Alt HTTP web interface",
    8554:  "Alt RTSP stream",
    8899:  "ONVIF / generic NVR",
    37777: "Dahua proprietary (DVRIP)",
    34567: "Generic Chinese DVR (Sofia)",
    9000:  "Foscam / management",
}

# Service banners / response hints → vendor fingerprint.
CAMERA_VENDOR_HINTS = {
    "hikvision": "Hikvision",
    "dahua":     "Dahua",
    "axis":      "Axis",
    "reolink":   "Reolink",
    "foscam":    "Foscam",
    "dvrip":     "Dahua",
    "sofia":     "Generic DVR",
    "boa/":      "Generic IP Camera",
    "server: webs": "Generic IP Camera",
    "hipcam":    "Generic IP Camera",
}

# Vendors that ship with well-known default credentials (used to flag *risk*,
# not to attempt logins — we never try the credentials).
KNOWN_DEFAULT_CRED_VENDORS = {
    "Hikvision":        "admin / 12345 (older firmware)",
    "Dahua":            "admin / admin",
    "Foscam":           "admin / (blank)",
    "Generic DVR":      "admin / admin or 888888",
    "Generic IP Camera":"admin / admin",
}


async def _probe_port(ip: str, port: int, timeout: float = 1.2) -> bool:
    """Non-blocking TCP connect check."""
    try:
        fut = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def _grab_http_banner(ip: str, port: int, timeout: float = 1.5) -> str:
    """Fetch a small HTTP response to fingerprint the device. Read-only."""
    scheme = "https" if port in (443,) else "http"
    url = f"{scheme}://{ip}:{port}/"
    try:
        async with httpx.AsyncClient(verify=False, timeout=timeout, follow_redirects=False) as client:
            r = await client.get(url)
            blob = (r.headers.get("server", "") + " " +
                    r.headers.get("www-authenticate", "") + " " +
                    r.text[:400]).lower()
            return blob
    except Exception:
        return ""


def _fingerprint_vendor(banners: str) -> Optional[str]:
    for hint, vendor in CAMERA_VENDOR_HINTS.items():
        if hint in banners:
            return vendor
    return None


async def scan_single_camera(ip: str) -> Optional[dict]:
    """Probe one host; return a camera record if it looks like a camera/NVR/DVR."""
    open_ports = []
    for port in CAMERA_PORTS:
        if await _probe_port(ip, port):
            open_ports.append(port)

    # Heuristic: a camera/NVR typically exposes a video port (RTSP/ONVIF/proprietary)
    # or a web UI on a camera-typical port.
    video_ports = {554, 8554, 37777, 34567, 8899}
    web_ports = {80, 443, 8000, 8080, 9000}
    if not open_ports or not (set(open_ports) & (video_ports | web_ports)):
        return None
    if not (set(open_ports) & video_ports) and not (set(open_ports) & web_ports):
        return None

    # Fingerprint via HTTP banner on any open web port.
    banners = ""
    for wp in (80, 8080, 8000, 443, 9000):
        if wp in open_ports:
            banners = await _grab_http_banner(ip, wp)
            if banners:
                break
    vendor = _fingerprint_vendor(banners) or "Unknown"

    has_video = bool(set(open_ports) & video_ports)
    default_cred_risk = vendor in KNOWN_DEFAULT_CRED_VENDORS

    return {
        "ip": ip,
        "manufacturer": vendor,
        "open_ports": open_ports,
        "rtsp": bool(set(open_ports) & {554, 8554}),
        "onvif": 8899 in open_ports,
        "web_ui": bool(set(open_ports) & web_ports),
        "default_cred_risk": default_cred_risk,
        "default_cred_hint": KNOWN_DEFAULT_CRED_VENDORS.get(vendor, ""),
        "has_video_service": has_video,
    }


def _expand_targets(network: str, max_hosts: int = 256) -> List[str]:
    """Expand a /24 (or single IP) into a host list. Conservative cap."""
    network = (network or "").strip()
    if "/" not in network:
        return [network] if network else []
    base, _, bits = network.partition("/")
    octets = base.split(".")
    if len(octets) != 4 or bits != "24":
        # Only support /24 and single IPs for safety/perf in this build.
        return [base]
    prefix = ".".join(octets[:3])
    return [f"{prefix}.{h}" for h in range(1, min(255, max_hosts))]


async def check_internet_exposure(public_ip: str) -> dict:
    """Check whether camera ports appear reachable on a PUBLIC ip.
    Only meaningful when the caller passes their own public IP."""
    if not public_ip:
        return {"checked": False}
    exposed = []
    for port in (80, 443, 554, 8000, 37777):
        if await _probe_port(public_ip, port, timeout=2.0):
            exposed.append({"port": port, "service": CAMERA_PORTS.get(port, "camera")})
    return {"checked": True, "public_ip": public_ip, "exposed_ports": exposed}


async def scan_camera_network(network: str, public_ip: str = "") -> dict:
    """Discover IP cameras on a /24 (or single IP) and assess each one.

    SECURITY NOTE: This performs TCP connect probes only. It never attempts
    to log in or use credentials — default-credential findings are advisory,
    based on vendor fingerprint, so the operator knows what to change.
    Only scan networks you own or are authorized to test.
    """
    targets = _expand_targets(network)
    if not targets:
        return {"error": "No valid network/IP provided", "cameras": []}

    # Probe hosts concurrently (bounded) for speed.
    sem = asyncio.Semaphore(40)
    async def _bounded(ip):
        async with sem:
            return await scan_single_camera(ip)

    results = await asyncio.gather(*[_bounded(ip) for ip in targets])
    cameras = [c for c in results if c]

    # Optional public-exposure check.
    exposure = await check_internet_exposure(public_ip) if public_ip else {"checked": False}
    publicly_exposed = bool(exposure.get("exposed_ports"))

    # Build findings + per-camera risk.
    for c in cameras:
        issues = []
        if c["default_cred_risk"]:
            issues.append({
                "severity": "critical",
                "title": "Possible default credentials",
                "description": f"{c['manufacturer']} devices commonly ship with default logins ({c['default_cred_hint']}).",
                "remediation": "Log in and set a unique strong password immediately; disable any guest/anonymous access.",
            })
        if c["rtsp"]:
            issues.append({
                "severity": "medium",
                "title": "RTSP stream port open (554/8554)",
                "description": "RTSP is reachable on the network. If not authenticated it may allow stream viewing.",
                "remediation": "Require authentication on RTSP, or disable it if you don't use external video clients.",
            })
        if 80 in c["open_ports"] or 8080 in c["open_ports"]:
            issues.append({
                "severity": "high",
                "title": "Unencrypted web interface (HTTP)",
                "description": "Management UI served over plain HTTP exposes credentials on the wire.",
                "remediation": "Use HTTPS only; disable the HTTP port.",
            })
        c["issues"] = issues
        c["at_risk"] = any(i["severity"] in ("critical", "high") for i in issues)

    default_cred = sum(1 for c in cameras if c["default_cred_risk"])
    at_risk = sum(1 for c in cameras if c["at_risk"])
    secured = sum(1 for c in cameras if not c["at_risk"])

    return {
        "network": network,
        "scanned_hosts": len(targets),
        "cameras": cameras,
        "total": len(cameras),
        "default_cred_count": default_cred,
        "at_risk_count": at_risk,
        "secured_count": secured,
        "internet_exposure": exposure,
        "publicly_exposed": publicly_exposed,
        "hardening": [
            "Change every default/factory password to a unique strong passphrase",
            "Put cameras on an isolated VLAN with no inbound internet access",
            "Disable UPnP on your router so cameras can't auto-open ports",
            "Use a VPN for remote viewing instead of port-forwarding",
            "Disable P2P / cloud-relay features you don't use",
            "Keep camera firmware updated; subscribe to vendor security advisories",
            "Disable RTSP/ONVIF if no external client needs them",
        ],
        "scanned_at": datetime.utcnow().isoformat(),
    }
