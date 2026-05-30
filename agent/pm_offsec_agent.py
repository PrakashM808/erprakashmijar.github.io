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
    args=parser.parse_args()
    cfg=load_config()
    if args.token: cfg['agent_token']=args.token
    if args.server: cfg['server']=args.server
    if not cfg.get('agent_token'):
        cfg['agent_token']=input("Agent Token: ").strip()
        cfg.setdefault('server',DEFAULT_SERVER)
        save_config(cfg)
    if args.scan:
        print(json.dumps(quick_scan(),indent=2)); sys.exit(0)
    run_agent(cfg.get('server',DEFAULT_SERVER),cfg['agent_token'])
