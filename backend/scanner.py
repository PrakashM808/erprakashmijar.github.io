"""
scanner.py — Security Scanner Engine
Supports: local machine scan + remote SSH scan
"""
import socket
import subprocess
import json
import re
import os
from datetime import datetime
from typing import Optional

# ── LOCAL SCAN FUNCTIONS ─────────────────────────────────────────

def get_hostname() -> str:
    return socket.gethostname()

def get_os_info() -> dict:
    try:
        with open('/etc/os-release') as f:
            lines = f.read()
        name = re.search(r'PRETTY_NAME="(.+)"', lines)
        return {"name": name.group(1) if name else "Unknown Linux", "type": "linux"}
    except:
        import platform
        return {"name": platform.system() + " " + platform.release(), "type": "other"}

def get_kernel() -> str:
    try:
        r = subprocess.run(['uname', '-r'], capture_output=True, text=True, timeout=5)
        return r.stdout.strip()
    except:
        return "unknown"

def get_uptime() -> str:
    try:
        with open('/proc/uptime') as f:
            secs = float(f.read().split()[0])
        days = int(secs // 86400)
        hours = int((secs % 86400) // 3600)
        mins = int((secs % 3600) // 60)
        return f"{days}d {hours}h {mins}m"
    except:
        return "unknown"

def scan_ports_local(ports: list = None) -> list:
    """Scan common ports on localhost"""
    if ports is None:
        ports = [21,22,23,25,53,80,443,3000,3306,5432,6379,8080,8443,8888,27017,6381,11211,9200]
    services = {
        21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",
        443:"HTTPS",3000:"Node.js",3306:"MySQL",5432:"PostgreSQL",
        6379:"Redis",8080:"HTTP-Alt",8443:"HTTPS-Alt",8888:"Jupyter",
        27017:"MongoDB",6381:"Redis-Alt",11211:"Memcached",9200:"Elasticsearch"
    }
    risk_map = {
        21:"critical",22:"medium",23:"critical",25:"medium",53:"low",
        80:"high",443:"low",3000:"medium",3306:"critical",5432:"high",
        6379:"critical",8080:"high",8443:"medium",8888:"high",
        27017:"critical",6381:"critical",11211:"high",9200:"high"
    }
    details = {
        21:"FTP exposes credentials in plaintext",
        22:"SSH — check for root login and key-based auth",
        23:"Telnet is unencrypted — replace with SSH immediately",
        25:"SMTP server exposed — check relay settings",
        53:"DNS service running",
        80:"Unencrypted HTTP traffic",
        443:"HTTPS — verify TLS version and certificate",
        3000:"Node.js dev server exposed",
        3306:"MySQL — verify not exposed to internet",
        5432:"PostgreSQL — verify access controls",
        6379:"Redis — check authentication config",
        8080:"Alt HTTP — dev server in production?",
        8443:"Alt HTTPS port",
        8888:"Jupyter Notebook — can allow code execution",
        27017:"MongoDB — verify authentication enabled",
        6381:"Redis alt port — verify auth",
        11211:"Memcached — no auth by default",
        9200:"Elasticsearch — verify auth enabled"
    }
    results = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex(('127.0.0.1', port))
            sock.close()
            if result == 0:
                results.append({
                    "port": port,
                    "service": services.get(port, "Unknown"),
                    "state": "open",
                    "risk": risk_map.get(port, "medium"),
                    "detail": details.get(port, f"Port {port} is open")
                })
        except:
            pass
    return results

def check_firewall_local() -> dict:
    for tool in ['ufw', 'firewalld', 'iptables']:
        try:
            if tool == 'ufw':
                r = subprocess.run(['ufw', 'status'], capture_output=True, text=True, timeout=5)
                status = 'active' if 'active' in r.stdout.lower() else 'inactive'
                return {"tool": "ufw", "status": status, "output": r.stdout[:500]}
            elif tool == 'firewalld':
                r = subprocess.run(['firewall-cmd', '--state'], capture_output=True, text=True, timeout=5)
                return {"tool": "firewalld", "status": r.stdout.strip(), "output": r.stdout}
            elif tool == 'iptables':
                r = subprocess.run(['iptables', '-L', '-n', '--line-numbers'], capture_output=True, text=True, timeout=5)
                rules = len([l for l in r.stdout.split('\n') if l.strip() and not l.startswith('Chain') and not l.startswith('target')])
                return {"tool": "iptables", "status": "active" if rules > 0 else "empty", "rules_count": rules}
        except FileNotFoundError:
            continue
        except Exception as e:
            continue
    return {"tool": "none", "status": "unknown", "output": "No firewall tool detected"}

def check_ssh_config_local() -> dict:
    config = {
        "root_login": "unknown",
        "password_auth": "unknown",
        "permit_empty_passwords": "unknown",
        "max_auth_tries": "unknown",
        "port": 22,
        "pubkey_auth": "unknown",
        "x11_forwarding": "unknown"
    }
    try:
        with open('/etc/ssh/sshd_config', 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith('#') or not line:
                    continue
                if 'PermitRootLogin' in line:
                    config['root_login'] = line.split()[-1].lower()
                elif 'PasswordAuthentication' in line:
                    config['password_auth'] = line.split()[-1].lower()
                elif 'PermitEmptyPasswords' in line:
                    config['permit_empty_passwords'] = line.split()[-1].lower()
                elif 'MaxAuthTries' in line:
                    config['max_auth_tries'] = line.split()[-1]
                elif line.startswith('Port '):
                    config['port'] = int(line.split()[-1])
                elif 'PubkeyAuthentication' in line:
                    config['pubkey_auth'] = line.split()[-1].lower()
                elif 'X11Forwarding' in line:
                    config['x11_forwarding'] = line.split()[-1].lower()
    except PermissionError:
        config['error'] = 'Permission denied — run with sudo'
    except FileNotFoundError:
        config['error'] = 'SSH config not found'
    return config

def check_failed_logins_local() -> dict:
    result = {"last_24h": 0, "unique_ips": 0, "top_ip": "none", "top_user": "none", "sample": []}
    log_files = ['/var/log/auth.log', '/var/log/secure', '/var/log/messages']
    for log_file in log_files:
        try:
            r = subprocess.run(
                ['grep', '-i', 'failed password\|invalid user\|authentication failure', log_file],
                capture_output=True, text=True, timeout=10
            )
            lines = [l for l in r.stdout.strip().split('\n') if l]
            ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', r.stdout)
            users = re.findall(r'(?:for|user) (\w+)', r.stdout)
            ip_count = {}
            for ip in ips:
                ip_count[ip] = ip_count.get(ip, 0) + 1
            user_count = {}
            for u in users:
                user_count[u] = user_count.get(u, 0) + 1
            top_ip = max(ip_count, key=ip_count.get) if ip_count else "none"
            top_user = max(user_count, key=user_count.get) if user_count else "none"
            result = {
                "last_24h": len(lines),
                "unique_ips": len(set(ips)),
                "top_ip": top_ip,
                "top_user": top_user,
                "sample": lines[:3]
            }
            break
        except (PermissionError, FileNotFoundError):
            continue
    return result

def check_outdated_packages_local() -> list:
    packages = []
    for cmd in [['apt', 'list', '--upgradable'], ['yum', 'check-update'], ['dnf', 'check-update']]:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if cmd[0] == 'apt':
                for line in r.stdout.split('\n')[1:]:
                    if '/' in line and line.strip():
                        parts = line.split()
                        name = parts[0].split('/')[0]
                        version = parts[1] if len(parts) > 1 else '?'
                        severity = 'critical' if name in ['openssl','openssh-server','linux-image','sudo','glibc'] else \
                                   'high' if name in ['curl','wget','apache2','nginx','php'] else 'medium'
                        packages.append({"name": name, "new_version": version, "severity": severity})
            break
        except FileNotFoundError:
            continue
        except Exception:
            break
    return packages[:10]

def check_file_permissions_local() -> list:
    checks = [
        ("/etc/passwd", "644", "low"),
        ("/etc/shadow", "640", "ok"),
        ("/etc/ssh/sshd_config", "600", "medium"),
        ("/tmp", "1777", "ok"),
        ("/var/log/auth.log", "640", "medium"),
        ("/root", "700", "high"),
        ("/etc/crontab", "644", "medium"),
    ]
    results = []
    for path, expected, risk_if_wrong in checks:
        try:
            import stat
            st = os.stat(path)
            actual = oct(st.st_mode)[-3:]
            is_ok = actual == expected or (path == '/etc/shadow' and actual in ['640','000','600'])
            results.append({
                "path": path,
                "perms": actual,
                "expected": expected,
                "risk": "ok" if is_ok else risk_if_wrong,
                "detail": f"Permissions OK ({actual})" if is_ok else f"Expected {expected}, got {actual}"
            })
        except (PermissionError, FileNotFoundError):
            results.append({"path": path, "perms": "???", "expected": expected, "risk": "unknown", "detail": "Cannot read"})
    return results

def check_users_local() -> list:
    users = []
    try:
        with open('/etc/passwd', 'r') as f:
            for line in f:
                parts = line.strip().split(':')
                if len(parts) < 7:
                    continue
                uid = int(parts[2])
                if uid == 0 or uid >= 1000:
                    shell = parts[6]
                    if '/nologin' in shell or '/false' in shell:
                        continue
                    users.append({
                        "name": parts[0],
                        "uid": uid,
                        "shell": shell,
                        "home": parts[5],
                        "sudo": False  # check below
                    })
        # check sudo
        try:
            r = subprocess.run(['getent', 'group', 'sudo'], capture_output=True, text=True, timeout=5)
            sudo_users = r.stdout.strip().split(':')[-1].split(',') if r.stdout else []
            for user in users:
                user['sudo'] = user['name'] in sudo_users or user['uid'] == 0
        except:
            pass
    except Exception as e:
        users = [{"error": str(e)}]
    return users[:10]

def check_disk_encryption_local() -> dict:
    try:
        r = subprocess.run(['lsblk', '-o', 'NAME,TYPE,MOUNTPOINT'], capture_output=True, text=True, timeout=5)
        has_crypt = 'crypt' in r.stdout.lower()
        return {"status": "encrypted" if has_crypt else "none", "detail": "LUKS detected" if has_crypt else "No disk encryption detected (LUKS not configured)"}
    except:
        return {"status": "unknown", "detail": "Could not check disk encryption"}

def calculate_score(data: dict) -> int:
    score = 100
    # Deduct for critical ports
    for port in data.get('open_ports', []):
        if port['risk'] == 'critical': score -= 12
        elif port['risk'] == 'high': score -= 6
        elif port['risk'] == 'medium': score -= 2
    # Firewall
    if data.get('firewall', {}).get('status') == 'inactive': score -= 15
    # SSH
    ssh = data.get('ssh_config', {})
    if ssh.get('root_login') == 'yes': score -= 10
    if ssh.get('password_auth') == 'yes': score -= 5
    # Failed logins
    logins = data.get('failed_logins', {}).get('last_24h', 0)
    if logins > 500: score -= 10
    elif logins > 100: score -= 5
    # Outdated packages
    pkgs = data.get('outdated_packages', [])
    criticals = [p for p in pkgs if p.get('severity') == 'critical']
    score -= len(criticals) * 5
    score -= len(pkgs) * 1
    # Disk encryption
    if data.get('disk_encryption', {}).get('status') == 'none': score -= 3
    return max(min(score, 100), 0)

def build_issues(data: dict) -> list:
    issues = []
    iid = 1
    for port in data.get('open_ports', []):
        if port['risk'] in ('critical', 'high'):
            cvss = 9.8 if port['risk'] == 'critical' else 7.2
            issues.append({"id": iid, "severity": port['risk'], "title": f"Port {port['port']} ({port['service']}) exposed", "category": "Network", "cvss": cvss, "detail": port['detail']})
            iid += 1
    ssh = data.get('ssh_config', {})
    if ssh.get('root_login') == 'yes':
        issues.append({"id": iid, "severity": "high", "title": "SSH root login enabled", "category": "SSH", "cvss": 7.5, "detail": "Direct root SSH increases brute-force impact"}); iid += 1
    if ssh.get('password_auth') == 'yes':
        issues.append({"id": iid, "severity": "medium", "title": "SSH password authentication enabled", "category": "SSH", "cvss": 5.3, "detail": "Switch to key-based auth only"}); iid += 1
    if data.get('firewall', {}).get('status') == 'inactive':
        issues.append({"id": iid, "severity": "high", "title": "Firewall is inactive", "category": "Network", "cvss": 7.2, "detail": "No ingress/egress filtering"}); iid += 1
    logins = data.get('failed_logins', {}).get('last_24h', 0)
    if logins > 100:
        issues.append({"id": iid, "severity": "high" if logins > 500 else "medium", "title": f"{logins} failed login attempts in 24h", "category": "Auth", "cvss": 7.0 if logins > 500 else 5.0, "detail": f"From {data['failed_logins'].get('unique_ips',0)} unique IPs"}); iid += 1
    for pkg in data.get('outdated_packages', []):
        if pkg.get('severity') in ('critical', 'high'):
            issues.append({"id": iid, "severity": pkg['severity'], "title": f"Outdated package: {pkg['name']}", "category": "Packages", "cvss": 8.1 if pkg['severity'] == 'critical' else 6.5, "detail": f"Update to {pkg.get('new_version','latest')}"}); iid += 1
    if data.get('disk_encryption', {}).get('status') == 'none':
        issues.append({"id": iid, "severity": "low", "title": "Disk encryption not configured", "category": "Storage", "cvss": 3.1, "detail": "LUKS not enabled"}); iid += 1
    return sorted(issues, key=lambda x: x['cvss'], reverse=True)

def local_scan() -> dict:
    """Full local system scan"""
    ports   = scan_ports_local()
    fw      = check_firewall_local()
    ssh     = check_ssh_config_local()
    logins  = check_failed_logins_local()
    pkgs    = check_outdated_packages_local()
    perms   = check_file_permissions_local()
    users   = check_users_local()
    disk    = check_disk_encryption_local()
    os_info = get_os_info()
    kernel  = get_kernel()
    uptime  = get_uptime()
    hostname = get_hostname()

    data = {
        "timestamp": datetime.now().isoformat(),
        "scan_type": "local",
        "hostname": hostname,
        "ip": "127.0.0.1",
        "os": os_info['name'],
        "kernel": kernel,
        "uptime": uptime,
        "open_ports": ports,
        "firewall": fw,
        "ssh_config": ssh,
        "failed_logins": logins,
        "outdated_packages": pkgs,
        "permissions": perms,
        "users": users,
        "disk_encryption": disk,
        "score_history": [],
    }
    data['security_score'] = calculate_score(data)
    data['issues'] = build_issues(data)
    return data


# ── REMOTE SCAN VIA SSH ─────────────────────────────────────────

def remote_scan(host: str, port: int = 22, username: str = "root",
                password: str = None, key_path: str = None) -> dict:
    """Scan a remote Linux machine via SSH"""
    try:
        import paramiko
    except ImportError:
        return {"error": "paramiko not installed. Run: pip install paramiko"}

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        connect_kwargs = {"hostname": host, "port": port, "username": username, "timeout": 15}
        if key_path:
            connect_kwargs["key_filename"] = os.path.expanduser(key_path)
        elif password:
            connect_kwargs["password"] = password
        else:
            connect_kwargs["key_filename"] = os.path.expanduser("~/.ssh/id_rsa")

        ssh.connect(**connect_kwargs)
    except paramiko.AuthenticationException:
        return {"error": "Authentication failed — check username/password/key"}
    except paramiko.NoValidConnectionsError:
        return {"error": f"Cannot connect to {host}:{port} — host unreachable or SSH not running"}
    except Exception as e:
        return {"error": f"Connection error: {str(e)}"}

    def run(cmd):
        try:
            _, stdout, stderr = ssh.exec_command(cmd, timeout=15)
            return stdout.read().decode('utf-8', errors='replace').strip()
        except:
            return ""

    # Collect data via SSH commands
    hostname  = run("hostname") or host
    os_name   = run("cat /etc/os-release | grep PRETTY_NAME | cut -d'\"' -f2") or "Linux"
    kernel    = run("uname -r")
    uptime_s  = run("awk '{print $1}' /proc/uptime")
    try:
        secs = float(uptime_s)
        uptime = f"{int(secs//86400)}d {int((secs%86400)//3600)}h {int((secs%3600)//60)}m"
    except:
        uptime = run("uptime -p") or "unknown"

    # Ports — use ss or netstat
    ports_raw = run("ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null")
    open_ports = _parse_remote_ports(ports_raw)

    # Firewall
    fw_raw = run("ufw status 2>/dev/null || firewall-cmd --state 2>/dev/null || iptables -L -n 2>/dev/null | head -5")
    firewall = {"status": "active" if "active" in fw_raw.lower() else "inactive", "output": fw_raw[:300]}

    # SSH config
    ssh_raw = run("cat /etc/ssh/sshd_config 2>/dev/null | grep -v '^#' | grep -v '^$'")
    ssh_config = _parse_ssh_config(ssh_raw)

    # Failed logins
    login_raw = run("grep -c 'Failed password\\|Invalid user' /var/log/auth.log 2>/dev/null || grep -c 'Failed password' /var/log/secure 2>/dev/null || echo 0")
    unique_ip_raw = run("grep 'Failed password' /var/log/auth.log 2>/dev/null | grep -oE '([0-9]{1,3}\\.){3}[0-9]{1,3}' | sort -u | wc -l || echo 0")
    top_ip_raw = run("grep 'Failed password' /var/log/auth.log 2>/dev/null | grep -oE '([0-9]{1,3}\\.){3}[0-9]{1,3}' | sort | uniq -c | sort -rn | head -1 | awk '{print $2}' || echo 'none'")
    failed_logins = {
        "last_24h": int(login_raw) if login_raw.isdigit() else 0,
        "unique_ips": int(unique_ip_raw) if unique_ip_raw.isdigit() else 0,
        "top_ip": top_ip_raw or "none",
        "top_user": "root"
    }

    # Packages
    pkg_raw = run("apt list --upgradable 2>/dev/null | tail -n +2 | head -10 || yum check-update 2>/dev/null | head -10")
    pkgs = _parse_remote_packages(pkg_raw)

    # Permissions
    perms = _check_remote_permissions(run)

    # Disk encryption
    lsblk_raw = run("lsblk -o NAME,TYPE,MOUNTPOINT 2>/dev/null")
    disk_enc = {"status": "encrypted" if "crypt" in lsblk_raw.lower() else "none",
                "detail": "LUKS detected" if "crypt" in lsblk_raw.lower() else "No LUKS encryption detected"}

    # Users
    users_raw = run("getent passwd | awk -F: '$3==0 || $3>=1000 {print $1,$3,$6,$7}'")
    sudo_raw  = run("getent group sudo 2>/dev/null || getent group wheel 2>/dev/null")
    users = _parse_remote_users(users_raw, sudo_raw)

    ssh.close()

    data = {
        "timestamp": datetime.now().isoformat(),
        "scan_type": "remote",
        "hostname": hostname,
        "ip": host,
        "os": os_name,
        "kernel": kernel,
        "uptime": uptime,
        "open_ports": open_ports,
        "firewall": firewall,
        "ssh_config": ssh_config,
        "failed_logins": failed_logins,
        "outdated_packages": pkgs,
        "permissions": perms,
        "users": users,
        "disk_encryption": disk_enc,
        "score_history": [],
    }
    data['security_score'] = calculate_score(data)
    data['issues'] = build_issues(data)
    return data


def _parse_remote_ports(raw: str) -> list:
    services = {21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",443:"HTTPS",
                3000:"Node.js",3306:"MySQL",5432:"PostgreSQL",6379:"Redis",8080:"HTTP-Alt",
                8443:"HTTPS-Alt",8888:"Jupyter",27017:"MongoDB",9200:"Elasticsearch",11211:"Memcached"}
    risk_map = {21:"critical",22:"medium",23:"critical",25:"medium",53:"low",80:"high",
                443:"low",3000:"medium",3306:"critical",5432:"high",6379:"critical",
                8080:"high",8443:"medium",8888:"high",27017:"critical",9200:"high",11211:"high"}
    found = []
    ports_seen = set()
    for line in raw.split('\n'):
        match = re.search(r':(\d+)\s', line)
        if match:
            port = int(match.group(1))
            if port not in ports_seen and port > 0:
                ports_seen.add(port)
                found.append({
                    "port": port,
                    "service": services.get(port, "Unknown"),
                    "state": "open",
                    "risk": risk_map.get(port, "medium"),
                    "detail": f"Port {port} listening"
                })
    return found[:20]

def _parse_ssh_config(raw: str) -> dict:
    config = {"root_login":"unknown","password_auth":"unknown","permit_empty_passwords":"unknown","max_auth_tries":"unknown","port":22,"pubkey_auth":"unknown"}
    for line in raw.split('\n'):
        parts = line.split()
        if len(parts) < 2: continue
        key, val = parts[0].lower(), parts[-1].lower()
        if 'permitrootlogin' in key: config['root_login'] = val
        elif 'passwordauthentication' in key: config['password_auth'] = val
        elif 'permitemptypasswords' in key: config['permit_empty_passwords'] = val
        elif 'maxauthtries' in key: config['max_auth_tries'] = val
        elif key == 'port': config['port'] = int(val) if val.isdigit() else 22
        elif 'pubkeyauthentication' in key: config['pubkey_auth'] = val
    return config

def _parse_remote_packages(raw: str) -> list:
    pkgs = []
    crit = ['openssl','openssh','linux-image','sudo','glibc','libc']
    high = ['curl','wget','apache2','nginx','php','python3']
    for line in raw.split('\n')[:10]:
        if not line.strip() or line.startswith('Listing'): continue
        name = line.split('/')[0].split()[0]
        sev = 'critical' if any(c in name for c in crit) else 'high' if any(h in name for h in high) else 'medium'
        version = line.split()[1] if len(line.split()) > 1 else 'latest'
        pkgs.append({"name": name, "new_version": version, "severity": sev})
    return pkgs

def _check_remote_permissions(run_fn) -> list:
    paths = ['/etc/passwd','/etc/shadow','/etc/ssh/sshd_config','/tmp','/var/log/auth.log','/root','/etc/crontab']
    results = []
    for path in paths:
        raw = run_fn(f"stat -c '%a %n' {path} 2>/dev/null")
        if raw:
            parts = raw.split()
            perms = parts[0] if parts else '???'
            results.append({"path": path, "perms": perms, "risk": "ok" if perms in ['644','640','600','700','755','1777'] else "medium", "detail": f"Permissions: {perms}"})
    return results

def _parse_remote_users(raw: str, sudo_raw: str) -> list:
    users = []
    sudo_list = sudo_raw.split(':')[-1].split(',') if sudo_raw else []
    for line in raw.split('\n')[:10]:
        parts = line.split()
        if not parts: continue
        name = parts[0]
        uid  = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        shell = parts[3] if len(parts) > 3 else '/bin/sh'
        if '/nologin' in shell or '/false' in shell: continue
        users.append({"name": name, "uid": uid, "shell": shell, "sudo": name in sudo_list or uid == 0})
    return users


# ── NETWORK DISCOVERY ────────────────────────────────────────────

def discover_network_devices(subnet: str = None) -> list:
    """Discover live hosts on the local subnet using ping sweep"""
    import ipaddress
    import threading

    if not subnet:
        # Auto-detect local subnet
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            local_ip = s.getsockname()[0]
            s.close()
            parts = local_ip.split('.')
            subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        except:
            subnet = "192.168.1.0/24"

    devices = []
    lock = threading.Lock()

    def ping_host(ip_str):
        try:
            r = subprocess.run(
                ['ping', '-c', '1', '-W', '1', str(ip_str)],
                capture_output=True, timeout=2
            )
            if r.returncode == 0:
                # Try to get hostname
                try:
                    hostname = socket.gethostbyaddr(str(ip_str))[0]
                except:
                    hostname = str(ip_str)
                # Quick port check
                open_ports = []
                for port in [22, 80, 443, 3306]:
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(0.3)
                        if sock.connect_ex((str(ip_str), port)) == 0:
                            open_ports.append(port)
                        sock.close()
                    except:
                        pass
                with lock:
                    devices.append({
                        "ip": str(ip_str),
                        "hostname": hostname,
                        "status": "online",
                        "open_ports": open_ports,
                        "ssh_available": 22 in open_ports,
                        "os_guess": "Linux" if 22 in open_ports else "Unknown"
                    })
        except:
            pass

    try:
        network = ipaddress.IPv4Network(subnet, strict=False)
        threads = []
        hosts = list(network.hosts())[:254]
        for ip in hosts:
            t = threading.Thread(target=ping_host, args=(ip,))
            t.daemon = True
            threads.append(t)
            t.start()
            if len(threads) % 20 == 0:
                for t in threads[-20:]:
                    t.join(timeout=2)
        for t in threads:
            t.join(timeout=2)
    except Exception as e:
        return [{"error": str(e)}]

    return sorted(devices, key=lambda x: [int(p) for p in x['ip'].split('.')])
