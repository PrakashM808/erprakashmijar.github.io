# PM::OFFSEC — Complete Upgrade Roadmap
## From Risk Indicator Platform → Enterprise Security Product

---

## PHASE 1 — Honest Launch (Weeks 1-2, ~$30/month)

### What gets fixed
- JWT auth on all endpoints ✅ (done in this build)
- Server-side IP validation ✅ (done in this build)  
- Scan result disclaimers ✅ (done in this build)
- Dark web "demo mode" label ✅ (done in this build)
- Compliance score disclaimer ✅ (done in this build)
- Audit logging to localStorage ✅ (done in this build)

### You need to do

**1. Connect Railway backend**
```bash
cd fullproject/backend
railway up
```

**2. Add PostgreSQL in Railway dashboard**
New Service → Database → PostgreSQL → Railway sets DATABASE_URL automatically

**3. Set all environment variables in Railway**
```
DATABASE_URL          = (auto-set)
JWT_SECRET_KEY        = (openssl rand -hex 32)
ANTHROPIC_API_KEY     = sk-ant-api03-...
SENDGRID_API_KEY      = SG.xxxxxxxxx
ALERT_FROM_EMAIL      = contact@erprakashmijar.com
HIBP_API_KEY          = (haveibeenpwned.com/API/Key)
VIRUSTOTAL_API_KEY    = (virustotal.com — free)
ABUSEIPDB_API_KEY     = (abuseipdb.com — free)
APP_URL               = https://erprakashmijar.com
PRODUCTION            = true
```

**4. Update Railway URL in dashboard**
Open dashboard/index.html → find `pm-offsec-backend-production.up.railway.app`
Replace with your real Railway domain

**5. Verify SendGrid domain authentication**
SendGrid → Settings → Sender Authentication → Authenticate erprakashmijar.com

**What you can sell after Phase 1:**
- Security monitoring and awareness platform
- Risk indicator scans for SMBs
- Phishing simulations
- Security consulting (you verify findings manually)
- Price: $19–$79/month

**Monthly cost: ~$30**
Railway ($10) + Anthropic (~$5) + HIBP ($3.50) + SendGrid (free) + VirusTotal (free)

---

## PHASE 2 — Real Vulnerability Scanner (Months 1-3, ~$150/month)

### Goal
Move from "risk indicators" to "confirmed vulnerabilities" by integrating open-source
security tools directly into your backend.

### Step 1 — Install Nuclei (Free, Open Source)

Nuclei by ProjectDiscovery is used by security teams at Google, Microsoft, and Amazon.
It has 9,000+ templates for confirmed vulnerabilities.

**Add to your Dockerfile:**
```dockerfile
# In fullproject/backend/Dockerfile, add:
RUN apt-get update && apt-get install -y golang-go wget
RUN wget https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip
RUN unzip nuclei_linux_amd64.zip && mv nuclei /usr/local/bin/
RUN nuclei -update-templates
```

**Add to scanner.py:**
```python
import subprocess, json

def run_nuclei_scan(target: str, severity: str = "critical,high,medium") -> list:
    """Run Nuclei vulnerability scanner against a target"""
    try:
        result = subprocess.run([
            'nuclei', '-target', target,
            '-severity', severity,
            '-json', '-silent',
            '-timeout', '30',
            '-rate-limit', '10',
            '-templates', '/root/nuclei-templates/'
        ], capture_output=True, text=True, timeout=120)
        
        findings = []
        for line in result.stdout.strip().split('\n'):
            if line:
                try:
                    finding = json.loads(line)
                    findings.append({
                        'title': finding.get('info', {}).get('name', ''),
                        'severity': finding.get('info', {}).get('severity', 'info'),
                        'cvss': finding.get('info', {}).get('cvss-score', 0),
                        'description': finding.get('info', {}).get('description', ''),
                        'matched_at': finding.get('matched-at', target),
                        'template_id': finding.get('template-id', ''),
                        'confirmed': True,  # Nuclei findings are confirmed
                        'reference': finding.get('info', {}).get('reference', [])
                    })
                except json.JSONDecodeError:
                    pass
        return findings
    except Exception as e:
        return []
```

**Add to main.py:**
```python
@app.post("/api/scan/nuclei")
async def nuclei_scan(req: RemoteScanReq, _user: dict = Depends(get_current_user)):
    """Confirmed vulnerability scan using Nuclei"""
    ip_ok, ip_msg = validate_scan_target(req.host)
    if not ip_ok:
        raise HTTPException(400, ip_msg)
    findings = run_nuclei_scan(req.host)
    return {"ok": True, "findings": findings, "confirmed": True, "scanner": "nuclei"}
```

**Why this matters:** Nuclei actually sends payloads to verify vulnerabilities exist.
Your current scanner checks config files. Nuclei confirms exploitability.

---

### Step 2 — Add OpenVAS for Deep Network Scanning (Free, Open Source)

OpenVAS is the open-source version of the enterprise tool used by CISA and NATO.

**Add to docker-compose.yml (new file in backend/):**
```yaml
version: '3.8'
services:
  backend:
    build: .
    ports:
      - "8000:8000"
    depends_on:
      - openvas
    environment:
      - OPENVAS_HOST=openvas
      
  openvas:
    image: greenbone/openvas-scanner
    ports:
      - "9390:9390"
    volumes:
      - openvas_data:/var/lib/openvas
      
volumes:
  openvas_data:
```

**Note:** OpenVAS needs 4GB+ RAM. Run on a separate DigitalOcean droplet
($24/month for 4GB) rather than Railway.

---

### Step 3 — Accurate CVE Version Matching

Replace the basic CVE lookup with proper version comparison:

**Add to cve.py:**
```python
from packaging import version
import re

def check_software_vulnerabilities(software_name: str, installed_version: str) -> list:
    """Match installed version against CVE database with proper semver comparison"""
    nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={software_name}&resultsPerPage=50"
    
    headers = {}
    if os.getenv("NVD_API_KEY"):
        headers["apiKey"] = os.getenv("NVD_API_KEY")
    
    try:
        import httpx
        response = httpx.get(nvd_url, headers=headers, timeout=10)
        cves = response.json().get("vulnerabilities", [])
        
        confirmed_vulns = []
        for cve_item in cves:
            cve = cve_item.get("cve", {})
            cve_id = cve.get("id", "")
            
            # Check if this CVE affects the installed version
            for config in cve.get("configurations", []):
                for node in config.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        if not match.get("vulnerable", False):
                            continue
                        version_end = match.get("versionEndIncluding") or match.get("versionEndExcluding")
                        version_start = match.get("versionStartIncluding", "0")
                        
                        if version_end and installed_version:
                            try:
                                inst = version.parse(installed_version)
                                end  = version.parse(version_end)
                                start = version.parse(version_start)
                                
                                if start <= inst <= end:
                                    metrics = cve.get("metrics", {})
                                    cvss_v3 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
                                    confirmed_vulns.append({
                                        "cve_id": cve_id,
                                        "score": cvss_v3.get("baseScore", 0),
                                        "severity": cvss_v3.get("baseSeverity", "UNKNOWN").lower(),
                                        "description": cve.get("descriptions", [{}])[0].get("value", ""),
                                        "affected_version": f"{version_start} - {version_end}",
                                        "installed_version": installed_version,
                                        "confirmed": True
                                    })
                            except Exception:
                                pass
        
        return confirmed_vulns
    except Exception as e:
        return []
```

**Cost:** Free with NVD_API_KEY (get at nvd.nist.gov — free registration)

---

### Step 4 — Real Shodan Integration

```python
# In osint.py - replace simulation with real Shodan data
import shodan

def shodan_host_lookup(ip: str) -> dict:
    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        return {"error": "Shodan API key not configured"}
    
    api = shodan.Shodan(api_key)
    try:
        host = api.host(ip)
        return {
            "ip": host["ip_str"],
            "org": host.get("org", "Unknown"),
            "os": host.get("os", "Unknown"),
            "ports": host.get("ports", []),
            "vulns": list(host.get("vulns", {}).keys()),
            "last_update": host.get("last_update", ""),
            "data": [
                {
                    "port": item["port"],
                    "service": item.get("product", "unknown"),
                    "version": item.get("version", ""),
                    "banner": item.get("data", "")[:200]
                }
                for item in host.get("data", [])
            ]
        }
    except shodan.exception.APIError as e:
        return {"error": str(e)}
```

**Cost:** Shodan API — $49/month. Worth it once you have 5+ paying customers.

**What you can sell after Phase 2:**
- Confirmed vulnerability scanning (with "powered by Nuclei" branding)
- Accurate CVE reports with version matching
- Real Shodan intelligence in OSINT reports
- Price: $79–$199/month justified
- Enterprise pentest report generation

**Monthly cost: ~$150**
Phase 1 ($30) + DigitalOcean for OpenVAS ($24) + Shodan ($49) + extras (~$50)

---

## PHASE 3 — Enterprise Platform (Months 3-6, ~$500/month)

### Goal
Build the infrastructure required to serve enterprise clients and MSPs.

### Step 1 — Real Dark Web Monitoring

**Option A — Flare.io API ($299/month)**
```python
# In main.py
import httpx

async def flare_dark_web_search(domain: str, api_key: str) -> list:
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "https://api.flare.io/firework/v2/activities/search",
            headers={"Authorization": f"Bearer {api_key}"},
            json={"query": domain, "from": 0, "size": 20}
        )
        results = response.json()
        return [
            {
                "type": item.get("type", "unknown"),
                "severity": "high" if "credential" in item.get("type","") else "medium",
                "title": item.get("title", ""),
                "detail": item.get("description", ""),
                "source": item.get("source", ""),
                "date": item.get("created_at", ""),
                "confirmed": True
            }
            for item in results.get("items", [])
        ]
```

**Option B — HIBP Enterprise ($3.50-$50/month depending on volume)**
Already integrated. Add HIBP_API_KEY and the breach data is real immediately.

**Option C — Build your own monitor (Free but 2 weeks work)**
Use Certificate Transparency logs, public paste monitoring,
and ransomware tracker RSS feeds:

```python
# Free dark web adjacent monitoring sources
MONITOR_SOURCES = [
    "https://ransomwatch.telemetry.ltd/feed.json",  # Ransomware tracker
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "https://feeds.feedburner.com/TheHackersNews",
]
```

---

### Step 2 — Evidence Collection for Compliance

Real compliance assessments need evidence, not just scores.

**Add to database.py:**
```python
# Evidence table
cur.execute("""
    CREATE TABLE IF NOT EXISTS compliance_evidence (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        framework TEXT NOT NULL,
        control_id TEXT NOT NULL,
        evidence_type TEXT NOT NULL,  -- screenshot, log, config, document
        file_path TEXT,
        description TEXT,
        collected_at TIMESTAMP DEFAULT NOW(),
        verified BOOLEAN DEFAULT FALSE,
        verified_by TEXT,
        verified_at TIMESTAMP
    )
""")
```

**Add to main.py:**
```python
@app.post("/api/compliance/evidence")
async def upload_evidence(
    framework: str,
    control_id: str,
    description: str,
    file: UploadFile = File(...),
    _user: dict = Depends(get_current_user)
):
    """Upload compliance evidence for a specific control"""
    evidence_id = str(uuid.uuid4())[:16]
    file_path = f"/evidence/{_user['user_id']}/{framework}/{control_id}/{evidence_id}"
    
    # Save to S3 or local storage
    content = await file.read()
    # In production: upload to S3
    # boto3.client('s3').put_object(Bucket='pm-offsec-evidence', Key=file_path, Body=content)
    
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO compliance_evidence VALUES (%s,%s,%s,%s,%s,%s,%s)",
            (evidence_id, _user['user_id'], framework, control_id, 
             file.content_type, file_path, description)
        )
    
    return {"ok": True, "evidence_id": evidence_id}
```

---

### Step 3 — Scan Result Storage and History

Right now scan results are in sessionStorage. Real enterprise clients need months of history.

**Add to database.py:**
```python
cur.execute("""
    CREATE TABLE IF NOT EXISTS scan_results (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        target_host TEXT NOT NULL,
        scan_type TEXT NOT NULL,
        score INTEGER,
        findings JSONB,
        raw_output TEXT,
        scanner_version TEXT,
        duration_seconds FLOAT,
        created_at TIMESTAMP DEFAULT NOW()
    )
""")
cur.execute("CREATE INDEX IF NOT EXISTS idx_scan_results_user ON scan_results(user_id)")
cur.execute("CREATE INDEX IF NOT EXISTS idx_scan_results_host ON scan_results(target_host)")
```

**Benefit:** Clients can see score trends over 90 days. This is what enterprise
security platforms charge $500/month for.

---

### Step 4 — Webhook and Slack Integration

```python
# In alerts.py
async def send_webhook_alert(webhook_url: str, finding: dict):
    """Send real-time alert to Slack, Teams, or any webhook"""
    payload = {
        "text": f"🚨 New {finding['severity'].upper()} finding: {finding['title']}",
        "attachments": [{
            "color": "danger" if finding['severity'] == 'critical' else "warning",
            "fields": [
                {"title": "Target", "value": finding.get('host', 'Unknown'), "short": True},
                {"title": "CVSS", "value": str(finding.get('cvss', 0)), "short": True},
                {"title": "Details", "value": finding.get('detail', '')[:200]}
            ],
            "footer": "PM::OFFSEC Security Dashboard",
            "ts": int(time.time())
        }]
    }
    async with httpx.AsyncClient() as client:
        await client.post(webhook_url, json=payload, timeout=10)
```

**What you can sell after Phase 3:**
- Real dark web monitoring ($99/month add-on)
- Compliance evidence collection for SOC 2 prep ($299/month)
- Trend reporting and executive dashboards
- MSP white-label platform ($499/month)
- Price justified up to $499/month

**Monthly cost: ~$500**
Phase 2 ($150) + Flare.io ($299) + S3 storage ($20) + extras (~$30)

---

## PHASE 4 — Certified Security Product (Months 6-18, $2,000-5,000 setup)

### Goal
Move from "security tool" to "security service" that can be sold to enterprises
and regulated industries.

### Step 1 — Partner With a Certified Pentester

You cannot issue certified penetration test reports without a licensed tester
signing off on findings. Options:

**Option A — Hire part-time**
Find a OSCP/CEH certified pentester on Upwork or LinkedIn.
Pay $50-100/hour to verify your tool's findings and co-sign reports.
Split revenue 70/30 with them.

**Option B — Subcontract model**
Partner with a small security firm. They provide certification credentials.
You provide the platform. Split: 60% you, 40% them.

**Option C — Get certified yourself**
- CEH (Certified Ethical Hacker) — ~$500, 3 months study
- OSCP (Offensive Security Certified Professional) — ~$1,500, 6 months study
- CompTIA Security+ — ~$380, 2 months study
With OSCP you can sign your own pentest reports.

---

### Step 2 — Professional Liability Insurance

Before any paid security work, get E&O (Errors and Omissions) insurance.

**Providers:**
- Hiscox — from $500/year for IT professionals
- Chubb — from $800/year
- Coalition — from $600/year (also covers cyber incidents)

**What it covers:**
- Client claims your scan caused a server outage
- Client claims you missed a vulnerability that was then exploited
- Client claims your report contained errors

Without this, one angry client can sue you personally.

---

### Step 3 — Your Own SOC 2 Type I Certification

For enterprise clients to trust your platform with their security data,
you need to show your OWN platform is secure.

SOC 2 Type I certifies your security controls at a point in time.
SOC 2 Type II (harder) certifies they work continuously over 6 months.

**Process:**
1. Implement required controls (access management, encryption, logging)
2. Hire a SOC 2 auditor ($8,000-$25,000)
3. 3-6 month audit process
4. Receive SOC 2 report to show enterprise clients

**Shortcut:** Use Vanta ($7,500/year) or Drata ($10,000/year) to automate
SOC 2 evidence collection. They can cut audit prep time from 6 months to 6 weeks.

---

### Step 4 — GDPR and HIPAA Compliance for Your Platform

If you scan healthcare clients or EU clients you need:

**For HIPAA:**
- Business Associate Agreement (BAA) template for healthcare clients
- Encrypt all PHI at rest (AES-256) and in transit (TLS 1.3)
- 90-day audit log retention
- Employee security training documentation

**For GDPR:**
- Data Processing Agreement (DPA) templates
- Data residency in EU (add EU Railway region)
- Right to erasure endpoint:
```python
@app.delete("/api/user/data/{user_id}")
async def delete_all_user_data(user_id: str, _user: dict = Depends(get_current_user)):
    """GDPR right to erasure — delete all user data"""
    if _user['user_id'] != user_id and _user.get('role') != 'admin':
        raise HTTPException(403, "Can only delete your own data")
    with get_db() as conn:
        cur = conn.cursor()
        for table in ['users','scan_results','compliance_evidence','incidents','alerts']:
            cur.execute(f"DELETE FROM {table} WHERE user_id = %s", (user_id,))
    return {"ok": True, "message": "All user data deleted"}
```

**What you can sell after Phase 4:**
- Certified penetration testing reports
- HIPAA-compliant security monitoring for healthcare
- GDPR-compliant monitoring for EU businesses
- Enterprise contracts ($1,000-$5,000/month)
- MSP white-label with your SOC 2 certification

---

## COMPLETE COST BREAKDOWN

| Phase | Monthly Cost | Time | What You Can Charge |
|-------|-------------|------|---------------------|
| Phase 1 | ~$30 | 2 weeks | $19-79/month |
| Phase 2 | ~$150 | 3 months | $79-199/month |
| Phase 3 | ~$500 | 6 months | $199-499/month |
| Phase 4 | ~$2,000 | 18 months | $500-5,000/month |

## CERTIFICATION PATH FOR YOU PERSONALLY

If you want to be the technical authority behind the platform:

```
Month 1-2:   CompTIA Security+        ($380 exam, 2 months study)
Month 3-4:   CEH — Certified Ethical Hacker   ($500 exam, 3 months)
Month 5-10:  OSCP — Offensive Security Certified Professional ($1,499)
Month 11-12: AWS Security Specialty   ($300 exam)
Year 2:      CISSP (requires 5 years experience)
```

After OSCP you can legally and credibly sign your own penetration test reports.
That is the single certification that most directly upgrades your platform from
"risk indicator tool" to "certified security service."

## THE SINGLE MOST IMPORTANT NEXT STEP

Before any of the above — deploy your backend, connect your first real client,
and do one manual scan + report for them. Everything else is theory until
you have a paying customer whose server you have actually scanned.

The platform is ready. The next upgrade is operational, not technical.
