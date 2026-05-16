# PM::OFFSEC — Complete Cybersecurity Portfolio + SOC Dashboard

## Project Structure
```
/
├── index.html                 Portfolio homepage
├── projects.html              Projects & case studies
├── labs.html                  Labs & platforms (THM, HTB, Bug Bounty)
├── skills.html                Offensive security skill stack
├── roadmap.html               Interactive ethical hacking roadmap
├── vibe-stack.html            Vibe coding stack 2026
├── about.html                 About & contact
├── login.html                 Login page (auth)
├── register.html              Register page (auth)
├── 404.html                   Custom error page
│
├── dashboard/
│   └── index.html             MEGA SOC DASHBOARD (all 17 pages)
│
├── billing/
│   ├── pricing.html           Pricing page (4 tiers, Stripe + LS toggle)
│   └── success.html           Post-payment success
│
├── projects/
│   └── wannacry.html          WannaCry malware analysis case study
│
├── assets/
│   ├── style.css              Portfolio shared styles
│   ├── home.css               Homepage styles
│   ├── shared.js              Canvas, cursor, nav
│   ├── auth.css               Login/register styles
│   └── auth.js                Auth system (register/login/sessions)
│
└── backend/                   Python FastAPI backend
    ├── main.py                REST API (all routes)
    ├── scanner.py             Local + remote SSH scanner
    ├── web_scanner.py         Website security scanner
    ├── osint.py               Email/IP/username OSINT
    ├── soc.py                 Incidents, IOCs, MITRE, Wazuh, Splunk
    ├── billing.py             Stripe + Lemon Squeezy payments
    ├── alerts.py              SendGrid email alerts
    ├── scheduler.py           APScheduler scheduled scans
    ├── requirements.txt
    └── .env.example
```

## Dashboard Pages (17 total)
| Page | Description |
|------|-------------|
| Dashboard | Overview, stats, activity feed, top issues |
| Devices | Multi-device management, re-scan, remove |
| Scanner | Live scan results (ports, SSH, packages, auth, perms) |
| Alerts | Security alerts with dismiss |
| AI Analysis | Claude-powered report + chat assistant |
| Reports | TXT + JSON export |
| Website Scanner | SSL, headers, DNS, exposed files, tech fingerprint |
| OSINT & Recon | Email breach check, password check, username lookup |
| Threat Intel | IP reputation (AbuseIPDB), VirusTotal, Shodan |
| Incidents | SOC incident management, timeline, MTTR |
| IOC Database | Indicators of compromise (IPs, domains, hashes) |
| MITRE ATT&CK | Automatic technique mapping from scan findings |
| Playbooks | 4 incident response playbooks with commands |
| Wazuh | Live Wazuh SIEM alerts and agent status |
| Splunk | Splunk search and log visualization |
| Admin Panel | User management, stats |
| Profile | Account settings |

## Auth System
- Register / Login with full validation and password strength
- 3 roles: admin / client / user
- Demo: admin@erprakashmijar.com / Admin@2026
- Sessions stored in localStorage (no server needed for auth)

## Pricing Tiers
| Plan | Price | Devices | Key Feature |
|------|-------|---------|-------------|
| Free | $0 | 1 | 1 scan/day |
| Starter | $19/mo | 5 | AI + email alerts |
| Professional | $79/mo | 25 | Scheduled scans + PDF |
| Enterprise | $199/mo | Unlimited | Full SOC suite |

## Backend Quick Start
```bash
cd backend
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Edit .env — add ANTHROPIC_API_KEY at minimum
python main.py
# API at http://localhost:8000 | Docs at http://localhost:8000/docs
```

## API Keys (what you need)
| Service | Free Tier | Used For |
|---------|-----------|----------|
| Anthropic | $5 credits | AI analysis + chat |
| SendGrid | 100 emails/day | Email alerts |
| HIBP | $3.50/month | Email breach check |
| AbuseIPDB | 1000/day free | IP reputation |
| VirusTotal | 4/min free | Malware lookup |
| Shodan | Limited free | Port/vuln intel |
| Stripe | % per transaction | Payments |
| Lemon Squeezy | % per transaction | Alt payments |

## Deploy Backend to Railway (free)
```bash
npm i -g @railway/cli
railway login && railway init && railway up
# Add env vars in Railway dashboard
```

## GitHub Deployment
Push everything in this folder to your GitHub repo.
GitHub Pages serves the frontend (HTML/CSS/JS) automatically.
Deploy the backend separately on Railway/Render/VPS.

## .gitignore (important)
Never commit backend/.env — it contains your API keys.
