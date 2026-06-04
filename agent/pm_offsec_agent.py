#!/usr/bin/env python3
"""PM::OFFSEC Device Agent v1.0 — runs on employee devices"""
import os,sys,json,time,platform,subprocess,socket,argparse,re
import urllib.request, urllib.error

DEFAULT_SERVER = "https://pm-offsec-backend-production.up.railway.app"
HEARTBEAT_SECS = 300
SCAN_INTERVAL  = 3600
CONFIG_FILE    = os.path.expanduser("~/.pm_offsec_agent.json")

def load_config():
    try:
        if os.path.exists(CONFIG_FILE):
            return json.load(open(CONFIG_FILE))
    except: pass
    return {}

def save_config(cfg):
    with open(CONFIG_FILE,'w') as f: json.dump(cfg,f,indent=2)
    try: os.chmod(CONFIG_FILE,0o600)
    except: pass

def api_post(server, path, data):
    url  = server.rstrip('/')+path
    body = json.dumps(data).encode()
    req  = urllib.request.Request(url,data=body,method='POST')
    req.add_header('Content-Type','application/json')
    try:
        with urllib.request.urlopen(req,timeout=10) as r:
            return json.loads(r.read())
    except Exception as e:
        return {"error":str(e)}

def get_local_ip():
    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        s.connect(("8.8.8.8",80)); ip=s.getsockname()[0]; s.close(); return ip
    except: return "127.0.0.1"

def get_mac():
    try:
        import uuid
        return ':'.join(('%012X'%uuid.getnode())[i:i+2] for i in range(0,12,2))
    except: return ""

def quick_scan():
    findings=[]; score=100
    if platform.system()!='Windows':
        ssh='/etc/ssh/sshd_config'
        if os.path.exists(ssh):
            try:
                txt=open(ssh).read()
                if re.search(r'^\s*PermitRootLogin\s+yes',txt,re.MULTILINE):
                    findings.append({"severity":"critical","title":"SSH Root Login Enabled","cvss":9.1,"category":"SSH"})
                    score-=20
                if re.search(r'^\s*PasswordAuthentication\s+yes',txt,re.MULTILINE):
                    findings.append({"severity":"high","title":"SSH Password Auth Enabled","cvss":7.2,"category":"SSH"})
                    score-=10
            except: pass
    if platform.system()=='Linux':
        try:
            r=subprocess.run(['ufw','status'],capture_output=True,text=True,timeout=5)
            if 'inactive' in r.stdout.lower():
                findings.append({"severity":"high","title":"Firewall Inactive","cvss":7.5,"category":"Firewall"})
                score-=15
        except: pass
    risky={21:'FTP',23:'Telnet',3306:'MySQL',5432:'PostgreSQL',6379:'Redis',27017:'MongoDB'}
    for port,svc in risky.items():
        try:
            s=socket.socket(); s.settimeout(0.3); s.connect(('127.0.0.1',port))
            findings.append({"severity":"medium","title":f"{svc} Open (:{port})","cvss":5.3,"category":"Network"})
            score-=5; s.close()
        except: pass
    if platform.system()=='Linux':
        try:
            r=subprocess.run(['apt','list','--upgradable','-q'],capture_output=True,text=True,timeout=10)
            n=len([l for l in r.stdout.strip().split('\n') if '/' in l])
            if n>5:
                sev="high" if n>20 else "medium"
                findings.append({"severity":sev,"title":f"{n} Packages Need Updates","cvss":7.0 if n>20 else 4.5,"category":"Packages"})
                score-=min(n//5,20)
        except: pass
    return {"score":max(score,0),"issues":findings,"hostname":socket.gethostname(),
            "ip":get_local_ip(),"os":platform.system()+' '+platform.version()[:50],
            "scanned_at":time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())}

# ── NETWORK WATCH: defensive monitoring of the user's OWN network ──
# Detection/reporting only. Uses the OS ARP table + local port checks (stdlib only).
WATCH_FILE = os.path.expanduser("~/.pm_offsec_netwatch.json")

def _load_watch():
    try:
        if os.path.exists(WATCH_FILE):
            return json.load(open(WATCH_FILE))
    except: pass
    return {"devices": {}, "ports": [], "gateway": None}

def _save_watch(state):
    try:
        json.dump(state, open(WATCH_FILE, 'w'), indent=2)
        os.chmod(WATCH_FILE, 0o600)
    except: pass

def get_arp_table():
    """Return {ip: mac} from the OS ARP/neighbour table. Read-only."""
    table = {}
    cmds = [['ip', 'neigh'], ['arp', '-a'], ['arp', '-n']]
    for cmd in cmds:
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=6).stdout
            if not out.strip():
                continue
            for line in out.splitlines():
                ipm = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', line)
                macm = re.search(r'([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})', line)
                if ipm and macm:
                    table[ipm.group(1)] = macm.group(1).lower()
            if table:
                break
        except Exception:
            continue
    return table

def get_default_gateway():
    """Return the default gateway IP (read-only)."""
    try:
        out = subprocess.run(['ip', 'route'], capture_output=True, text=True, timeout=5).stdout
        m = re.search(r'default via (\d{1,3}(?:\.\d{1,3}){3})', out)
        if m:
            return m.group(1)
    except Exception:
        pass
    try:
        out = subprocess.run(['netstat', '-rn'], capture_output=True, text=True, timeout=5).stdout
        for line in out.splitlines():
            if line.split()[:1] == ['0.0.0.0'] or line.startswith('default'):
                m = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', line)
                if m:
                    return m.group(1)
    except Exception:
        pass
    return None

def scan_local_open_ports():
    """Which common ports are open on THIS device (loopback). Read-only."""
    ports = [21,22,23,25,53,80,135,139,443,445,3306,3389,5432,6379,8080,27017]
    open_ports = []
    for p in ports:
        try:
            s = socket.socket(); s.settimeout(0.3)
            if s.connect_ex(('127.0.0.1', p)) == 0:
                open_ports.append(p)
            s.close()
        except Exception:
            pass
    return open_ports

def network_watch():
    """Compare current network state to the saved baseline; report anomalies.
    Returns a list of {severity,type,title,detail} suspicious-activity findings."""
    prev = _load_watch()
    alerts = []
    arp = get_arp_table()
    gateway = get_default_gateway()

    # 1) New / unknown devices on the network
    known = prev.get("devices", {})
    for ip, mac in arp.items():
        if ip not in known:
            # first run seeds the baseline silently; afterwards, new = noteworthy
            if known:
                alerts.append({"severity":"medium","type":"new_device",
                    "title":"New device joined the network",
                    "detail":"{} ({})".format(ip, mac)})
        elif known.get(ip) and known[ip] != mac:
            # IP now answers with a different MAC — possible spoofing/impersonation
            alerts.append({"severity":"high","type":"mac_changed",
                "title":"Device MAC address changed",
                "detail":"{}: {} -> {}".format(ip, known[ip], mac)})

    # 2) ARP spoofing: one MAC claiming many IPs, or gateway with multiple MACs
    mac_to_ips = {}
    for ip, mac in arp.items():
        mac_to_ips.setdefault(mac, []).append(ip)
    for mac, ips in mac_to_ips.items():
        if len(ips) >= 3:
            alerts.append({"severity":"critical","type":"arp_spoof",
                "title":"Possible ARP spoofing (man-in-the-middle)",
                "detail":"MAC {} is claiming {} IPs: {}".format(mac, len(ips), ", ".join(ips[:5]))})

    # 3) Gateway changed (possible router hijack / rogue gateway)
    if prev.get("gateway") and gateway and prev["gateway"] != gateway:
        alerts.append({"severity":"critical","type":"gateway_changed",
            "title":"Default gateway changed",
            "detail":"{} -> {}".format(prev["gateway"], gateway)})

    # 4) New open ports on this device since last check
    cur_ports = scan_local_open_ports()
    prev_ports = prev.get("ports", [])
    new_ports = [p for p in cur_ports if p not in prev_ports]
    if prev_ports and new_ports:
        alerts.append({"severity":"medium","type":"new_port",
            "title":"New open port detected on this device",
            "detail":"Newly listening: {}".format(", ".join(str(p) for p in new_ports))})

    # Save the new baseline
    _save_watch({"devices": arp, "ports": cur_ports, "gateway": gateway})

    return {
        "device_count": len(arp),
        "gateway": gateway,
        "open_ports": cur_ports,
        "alerts": alerts,
        "checked_at": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    }

def run_agent(server, agent_token):
    print(f"[PM::OFFSEC Agent] Started | server={server} | token={agent_token[:8]}...")
    last_scan=0
    while True:
        try:
            r=api_post(server,'/api/org/devices/heartbeat',{'agent_token':agent_token,'ip_address':get_local_ip()})
            ts=time.strftime('%H:%M:%S')
            print(f"[{ts}] Heartbeat {'OK' if r.get('ok') else 'FAIL: '+str(r.get('error',''))}")
            if time.time()-last_scan>SCAN_INTERVAL:
                print(f"[{ts}] Scanning...")
                scan=quick_scan()
                api_post(server,'/api/org/devices/heartbeat',{'agent_token':agent_token,'score':scan['score'],'ip_address':scan['ip']})
                print(f"[{ts}] Score={scan['score']}/100 Issues={len(scan['issues'])}")
                # Network Watch — report any suspicious activity on the local network
                try:
                    nw=network_watch()
                    if nw['alerts']:
                        api_post(server,'/api/org/netwatch',{'agent_token':agent_token,
                            'alerts':nw['alerts'],'device_count':nw['device_count'],
                            'gateway':nw['gateway'],'checked_at':nw['checked_at']})
                        for a in nw['alerts']:
                            print(f"[{ts}] \u26a0 {a['severity'].upper()}: {a['title']} — {a['detail']}")
                    else:
                        print(f"[{ts}] Network Watch: {nw['device_count']} devices, no suspicious activity")
                except Exception as e:
                    print(f"[{ts}] Network Watch error: {e}")
                last_scan=time.time()
        except KeyboardInterrupt:
            print("\n[Agent] Stopped."); break
        except Exception as e:
            print(f"[Agent] Error: {e}")
        time.sleep(HEARTBEAT_SECS)

if __name__=='__main__':
    parser=argparse.ArgumentParser(description='PM::OFFSEC Device Agent')
    parser.add_argument('--token',help='Agent token'); parser.add_argument('--server',help='Backend URL')
    parser.add_argument('--scan',action='store_true',help='One scan and exit')
    parser.add_argument('--netwatch',action='store_true',help='Run one network watch and exit')
    args=parser.parse_args()
    cfg=load_config()
    if args.token: cfg['agent_token']=args.token
    if args.server: cfg['server']=args.server
    if args.netwatch:
        print(json.dumps(network_watch(),indent=2)); sys.exit(0)
    if not cfg.get('agent_token'):
        cfg['agent_token']=input("Agent Token: ").strip()
        cfg.setdefault('server',DEFAULT_SERVER)
        save_config(cfg)
    if args.scan:
        print(json.dumps(quick_scan(),indent=2)); sys.exit(0)
    run_agent(cfg.get('server',DEFAULT_SERVER),cfg['agent_token'])
