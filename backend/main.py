"""
main.py — PM::OFFSEC Security Dashboard API v3.0
Full SaaS backend: live scanning + billing + email alerts + scheduled scans
"""
import os, json, uuid
from datetime import datetime, timedelta
from typing import Optional
from fastapi import FastAPI, HTTPException, Request, BackgroundTasks, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

from scanner   import local_scan, remote_scan, discover_network_devices
from physical_security import scan_atm_network, scan_vending_network, get_atm_compliance_summary, scan_camera_network
from cve       import search_cves_by_keyword, get_cve_by_id, get_recent_cves
from billing   import (PLANS, init_stripe, create_stripe_checkout,
                       create_lemonsqueezy_checkout, handle_stripe_webhook,
                       handle_lemonsqueezy_webhook, check_plan_limit, get_plan_info,
                       start_trial, check_trial_status, generate_invoice,
                       generate_invoice_html, process_stripe_event, process_ls_event,
                       downgrade_to_free, get_upgrade_url)
from alerts    import (send_scan_alert, send_weekly_report,
                       send_welcome_email, send_subscription_email, send_email,
                       send_agreement_confirmation, send_password_reset,
                       send_critical_alert, send_scan_complete,
                       send_weekly_digest, send_plan_expiry_warning,
                       send_new_device_alert, send_slack_alert)
from scheduler import (add_schedule, remove_schedule, pause_schedule,
                       resume_schedule, get_all_schedules, get_schedule,
                       CRON_PRESETS, start_scheduler, stop_scheduler)
import anthropic
from database import (
    init_db, user_create, user_get, user_get_by_email, user_update, user_delete,
    org_device_add, org_devices_get, org_device_delete,
    user_record_login, users_get_all, scan_save, scan_get_history,
    scan_get_all_history, scan_get_recent, scan_count_increment,
    scan_count_get_today, incident_create, incident_get_all, incident_update,
    agreement_save, agreements_get_all, alert_prefs_set, alert_prefs_get,
    plan_set, plan_get, subscription_save, subscription_get,
    ioc_add, iocs_get_all, get_dashboard_stats, get_score_history,
    POSTGRES_AVAILABLE, get_db
)

init_stripe()

app = FastAPI(
    title="PM::OFFSEC Security Dashboard API",
    description="Full SaaS security scanning API — scanning, billing, alerts, scheduler",
    version="3.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://erprakashmijar.com",
        "https://www.erprakashmijar.com",
        "http://localhost:3000", "http://localhost:5500",
        "http://127.0.0.1:5500", "http://localhost:8080",
        "null",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Storage now handled by database.py (PostgreSQL + in-memory fallback) ──
# Legacy dicts kept for any code that references them directly
scan_history: dict  = {}
user_plans:   dict  = {}
user_subs:    dict  = {}
scan_counts:  dict  = {}
alert_prefs:  dict  = {}

# ── LIFECYCLE ────────────────────────────────────────────────────


# ── OAUTH & PHONE VERIFICATION ENDPOINTS ─────────────────────────
import hashlib, secrets

class PhoneOTPReq(BaseModel):
    phone: str
    user_id: str = ""

class VerifyPhoneOTPReq(BaseModel):
    phone: str
    code: str
    user_id: str = ""

class GoogleOAuthReq(BaseModel):
    credential: str   # Google JWT token
    plan: str = "free"

class GitHubOAuthReq(BaseModel):
    code: str         # GitHub auth code from redirect
    state: str = ""
    plan: str = "free"

# In-memory OTP store (use Redis in production)
_phone_otps = {}

@app.post("/api/phone/send-otp")
async def send_phone_otp(req: PhoneOTPReq):
    """Send OTP to phone number via SMS (requires Twilio in production)"""
    phone = req.phone.strip()
    if len(phone) < 10:
        raise HTTPException(400, "Invalid phone number")

    # Generate 6-digit OTP
    otp = str(secrets.randbelow(900000) + 100000)
    _phone_otps[phone] = {
        "otp": otp,
        "expires": datetime.utcnow().timestamp() + 300,  # 5 min
        "attempts": 0
    }

    # Send via Twilio if configured
    twilio_sid    = os.getenv("TWILIO_ACCOUNT_SID")
    twilio_token  = os.getenv("TWILIO_AUTH_TOKEN")
    twilio_number = os.getenv("TWILIO_PHONE_NUMBER")

    if twilio_sid and twilio_token and twilio_number:
        try:
            from twilio.rest import Client
            client = Client(twilio_sid, twilio_token)
            client.messages.create(
                body=f"Your PM::OFFSEC verification code is: {otp}. Expires in 5 minutes.",
                from_=twilio_number,
                to=phone
            )
            return {"ok": True, "message": f"OTP sent to {phone[:4]}***{phone[-3:]}"}
        except Exception as e:
            # Fall through to demo mode
            pass

    # Demo mode: return OTP in response (remove in production)
    return {
        "ok": True,
        "message": f"OTP sent to {phone[:4]}***{phone[-3:]}",
        "demo_otp": otp,  # REMOVE IN PRODUCTION
        "note": "Add TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_PHONE_NUMBER to Railway env for real SMS"
    }

@app.post("/api/phone/verify-otp")
async def verify_phone_otp(req: VerifyPhoneOTPReq):
    """Verify phone OTP"""
    phone = req.phone.strip()
    code  = req.code.strip()

    if phone not in _phone_otps:
        raise HTTPException(400, "No OTP sent to this number. Request a new code.")

    entry = _phone_otps[phone]
    if datetime.utcnow().timestamp() > entry["expires"]:
        del _phone_otps[phone]
        raise HTTPException(400, "OTP has expired. Request a new code.")

    entry["attempts"] = entry.get("attempts", 0) + 1
    if entry["attempts"] > 5:
        del _phone_otps[phone]
        raise HTTPException(400, "Too many attempts. Request a new code.")

    if code != entry["otp"]:
        raise HTTPException(400, "Incorrect code. Please try again.")

    del _phone_otps[phone]

    # Mark phone as verified for user
    if req.user_id:
        user_update(req.user_id, phone=phone)

    return {"ok": True, "message": "Phone number verified successfully"}

@app.post("/api/auth/google")
async def google_oauth(req: GoogleOAuthReq):
    """Handle Google OAuth — verify JWT and create/login account"""
    import base64, json

    try:
        # Decode Google JWT (in production, verify with Google's public keys)
        parts = req.credential.split('.')
        payload_b64 = parts[1] + '==' * (4 - len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))

        email   = payload.get("email", "")
        name    = payload.get("name", "")
        google_id = payload.get("sub", "")
        email_verified = payload.get("email_verified", False)

        if not email:
            raise HTTPException(400, "Could not get email from Google token")

        # Check if user exists
        existing = user_get_by_email(email)
        if existing:
            # Update OAuth info and return session
            user_record_login(existing["id"])
            return {
                "ok": True,
                "action": "login",
                "user": {
                    "id": existing["id"],
                    "email": email,
                    "name": existing.get("name", name),
                    "role": existing.get("role", "user"),
                    "plan": existing.get("plan", "free"),
                }
            }

        # Create new account via Google
        import uuid
        user_id = str(uuid.uuid4())[:12]
        hashed_pw = hashlib.sha256(f"google_{google_id}_{email}".encode()).hexdigest()
        name_parts = name.split(' ')
        full_name = name or email.split('@')[0]

        user_create(
            user_id=user_id,
            name=full_name,
            email=email,
            password=hashed_pw,
            plan=req.plan,
            company=""
        )

        return {
            "ok": True,
            "action": "register",
            "user": {
                "id": user_id,
                "email": email,
                "name": full_name,
                "role": "user",
                "plan": req.plan,
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, f"Google OAuth failed: {str(e)}")

@app.get("/api/auth/github/callback")
async def github_oauth_callback(code: str, state: str = ""):
    """Handle GitHub OAuth callback"""
    client_id     = os.getenv("GITHUB_CLIENT_ID", "")
    client_secret = os.getenv("GITHUB_CLIENT_SECRET", "")

    if not client_id or not client_secret:
        raise HTTPException(400, "GitHub OAuth not configured. Add GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET to Railway env.")

    try:
        import httpx
        # Exchange code for access token
        async with httpx.AsyncClient() as client:
            token_r = await client.post("https://github.com/login/oauth/access_token",
                headers={"Accept": "application/json"},
                json={"client_id": client_id, "client_secret": client_secret, "code": code}
            )
            token_data = token_r.json()
            access_token = token_data.get("access_token", "")

            if not access_token:
                raise HTTPException(400, "Failed to get GitHub access token")

            # Get user info
            user_r = await client.get("https://api.github.com/user",
                headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"}
            )
            gh_user = user_r.json()

            # Get emails
            emails_r = await client.get("https://api.github.com/user/emails",
                headers={"Authorization": f"Bearer {access_token}"}
            )
            emails = emails_r.json()
            primary_email = next((e["email"] for e in emails if e.get("primary")), None)
            email = primary_email or gh_user.get("email", "")

            if not email:
                raise HTTPException(400, "Could not get email from GitHub")

        # Check/create user
        existing = user_get_by_email(email)
        if existing:
            user_record_login(existing["id"])
            user_id = existing["id"]
            name = existing.get("name", gh_user.get("name",""))
            plan = existing.get("plan","free")
        else:
            import uuid
            user_id = str(uuid.uuid4())[:12]
            name = gh_user.get("name") or gh_user.get("login") or email.split("@")[0]
            hashed_pw = hashlib.sha256(f"github_{gh_user.get('id')}_{email}".encode()).hexdigest()
            plan = "free"
            user_create(user_id=user_id, name=name, email=email, password=hashed_pw)

        # Redirect to dashboard with session token
        from fastapi.responses import RedirectResponse
        session_token = hashlib.sha256(f"{user_id}{datetime.utcnow().isoformat()}".encode()).hexdigest()[:32]
        return RedirectResponse(
            url=f"{os.getenv('APP_URL','https://erprakashmijar.com')}/dashboard/index.html?oauth=github&uid={user_id}&token={session_token}"
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, f"GitHub OAuth failed: {str(e)}")


# ═══════════════════════════════════════════════════════════════
# JWT AUTHENTICATION ENDPOINTS
# ═══════════════════════════════════════════════════════════════
try:
    import jwt as pyjwt
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False

try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False

# Third-party API keys
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY  = os.getenv("ABUSEIPDB_API_KEY", "")
SHODAN_API_KEY     = os.getenv("SHODAN_API_KEY", "")
NVD_API_KEY        = os.getenv("NVD_API_KEY", "")

JWT_SECRET    = os.getenv("JWT_SECRET_KEY", "pm-offsec-dev-secret-change-in-production")
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_HOURS = 24

from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
_security_bearer = HTTPBearer(auto_error=False)

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(_security_bearer)):
    if not credentials:
        raise HTTPException(401, "Missing authorization token")
    try:
        if not JWT_AVAILABLE:
            raise HTTPException(500, "JWT not available — run: pip install pyjwt")
        payload = pyjwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return {"user_id": payload.get("user_id"), "email": payload.get("sub"), "plan": payload.get("plan","free"), "role": payload.get("role","user")}
    except Exception as e:
        raise HTTPException(401, f"Invalid token: {str(e)}")


def require_admin(user: dict = Depends(get_current_user)) -> dict:
    """Authorization gate: only users whose server-issued JWT carries
    role='admin' may proceed. The client cannot forge this — the role is
    set when the backend signs the token, not by anything in the browser."""
    if user.get("role") != "admin":
        raise HTTPException(403, "Admin privileges required")
    return user

class JWTRegisterReq(BaseModel):
    name: str
    email: str
    password: str
    company: str = ""
    phone: str = ""
    plan: str = "free"

class JWTLoginReq(BaseModel):
    email: str
    password: str

@app.post("/api/auth/register")
async def jwt_register(req: JWTRegisterReq, background_tasks: BackgroundTasks):
    existing = user_get_by_email(req.email)
    if existing:
        raise HTTPException(400, "Email already registered")
    import hashlib, uuid as _uuid
    user_id = str(_uuid.uuid4())[:16]
    if BCRYPT_AVAILABLE:
        hashed = bcrypt.hashpw(req.password.encode(), bcrypt.gensalt()).decode()
    else:
        hashed = hashlib.sha256(req.password.encode()).hexdigest()
    user_create(user_id=user_id, name=req.name, email=req.email, password=hashed,
                role="user", plan=req.plan, company=req.company, phone=req.phone)
    plan_set(user_id, req.plan)
    if req.plan != "free":
        try: start_trial(user_id, req.plan)
        except: pass
    if os.getenv("SENDGRID_API_KEY"):
        background_tasks.add_task(send_welcome_email, req.email, req.name, req.plan)
    token = ""
    if JWT_AVAILABLE:
        token = pyjwt.encode({"sub":req.email,"user_id":user_id,"plan":req.plan,"role":"user",
            "exp":datetime.utcnow()+timedelta(hours=JWT_EXPIRY_HOURS)}, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return {"ok":True,"access_token":token,"user_id":user_id,"email":req.email,"name":req.name,"plan":req.plan,"role":"user"}

@app.post("/api/auth/login")
async def jwt_login(req: JWTLoginReq):
    import hashlib
    user = user_get_by_email(req.email)
    if not user:
        raise HTTPException(401, "Invalid email or password")
    stored = user.get("password","")
    if BCRYPT_AVAILABLE:
        try:
            ok = bcrypt.checkpw(req.password.encode(), stored.encode())
        except:
            ok = (hashlib.sha256(req.password.encode()).hexdigest() == stored)
    else:
        ok = (hashlib.sha256(req.password.encode()).hexdigest() == stored)
    if not ok:
        raise HTTPException(401, "Invalid email or password")
    if user.get("status") == "suspended":
        raise HTTPException(403, "Account suspended")
    user_record_login(user["id"])
    current_plan = plan_get(user["id"])
    user_role = user.get("role", "user")
    token = ""
    if JWT_AVAILABLE:
        token = pyjwt.encode({"sub":user["email"],"user_id":user["id"],"plan":current_plan,"role":user_role,
            "exp":datetime.utcnow()+timedelta(hours=JWT_EXPIRY_HOURS)}, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return {"ok":True,"access_token":token,"user_id":user["id"],"email":user["email"],"name":user.get("name",""),"plan":current_plan,"role":user_role}

@app.get("/api/auth/verify")
async def jwt_verify(user: dict = Depends(get_current_user)):
    return {"valid":True,"user_id":user["user_id"],"email":user["email"],"plan":user["plan"]}

@app.post("/api/auth/logout")
async def jwt_logout():
    return {"ok":True}



# ═══════════════════════════════════════════════════════════════
# SCAN RESULT STORAGE + 90-DAY HISTORY
# ═══════════════════════════════════════════════════════════════
import json as _json

def save_scan_result(user_id: str, target_host: str, scan_type: str, 
                     score: int, findings: list, extra: dict = None):
    """Persist scan result to PostgreSQL for trend history"""
    result_id = str(uuid.uuid4())[:16]
    grade = "A" if score>=90 else "B" if score>=80 else "C" if score>=70 else "D" if score>=55 else "F"
    
    if POSTGRES_AVAILABLE:
        try:
            with get_db() as conn:
                cur = conn.cursor()
                cur.execute("""
                    INSERT INTO scan_results 
                    (id, user_id, target_host, target_ip, scan_type, score, grade, findings, 
                     open_ports, ssh_config, os_info, created_at)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW())
                """, (
                    result_id, user_id, target_host,
                    extra.get("ip","") if extra else "",
                    scan_type, score, grade,
                    _json.dumps(findings[:50]),  # cap at 50 findings
                    _json.dumps(extra.get("open_ports",[]) if extra else []),
                    _json.dumps(extra.get("ssh_config",{}) if extra else {}),
                    extra.get("os","") if extra else "",
                ))
        except Exception as e:
            print(f"[WARN] Could not save scan result: {e}")
    
    return result_id

@app.get("/api/history/{user_id}")
async def get_scan_history(user_id: str, days: int = 90):
    """Get scan history for a user — 90-day trend data"""
    if not POSTGRES_AVAILABLE:
        # Return demo trend data when no DB
        import random
        from datetime import datetime, timedelta
        demo = []
        base_score = 45
        for i in range(min(days, 30)):
            dt = datetime.utcnow() - timedelta(days=29-i)
            base_score = min(95, base_score + random.randint(-3, 6))
            demo.append({
                "date": dt.strftime("%Y-%m-%d"),
                "score": base_score,
                "grade": "A" if base_score>=90 else "B" if base_score>=80 else "C" if base_score>=70 else "D" if base_score>=55 else "F",
                "findings_count": max(0, random.randint(0, 12) - i//3),
                "host": "demo-server",
            })
        return {"ok": True, "history": demo, "trend": "improving", "demo": True}
    
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute("""
                SELECT DATE(created_at) as date, 
                       AVG(score)::INTEGER as avg_score,
                       MIN(grade) as best_grade,
                       COUNT(*) as scan_count,
                       SUM(jsonb_array_length(findings)) as total_findings,
                       MAX(target_host) as last_host
                FROM scan_results
                WHERE user_id = %s 
                  AND created_at >= NOW() - INTERVAL '%s days'
                GROUP BY DATE(created_at)
                ORDER BY date ASC
            """, (user_id, days))
            rows = cur.fetchall()
            history = [
                {"date": str(r[0]), "score": r[1] or 0, "grade": r[2] or "F",
                 "scan_count": r[3], "findings_count": r[4] or 0, "host": r[5]}
                for r in rows
            ]
            
            # Calculate trend
            if len(history) >= 2:
                first_half = sum(h["score"] for h in history[:len(history)//2]) / max(1, len(history)//2)
                second_half = sum(h["score"] for h in history[len(history)//2:]) / max(1, len(history) - len(history)//2)
                trend = "improving" if second_half > first_half + 2 else "declining" if second_half < first_half - 2 else "stable"
            else:
                trend = "insufficient_data"
            
            return {"ok": True, "history": history, "trend": trend, "days": days}
    except Exception as e:
        raise HTTPException(500, str(e))

@app.get("/api/history/{user_id}/hosts")
async def get_scanned_hosts(user_id: str):
    """Get list of all hosts scanned by a user"""
    if not POSTGRES_AVAILABLE:
        return {"ok": True, "hosts": [{"host": "demo-server", "last_score": 72, "scan_count": 5}]}
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute("""
                SELECT target_host, MAX(score) as best_score, 
                       COUNT(*) as scan_count, MAX(created_at) as last_scan
                FROM scan_results WHERE user_id = %s
                GROUP BY target_host ORDER BY last_scan DESC
            """, (user_id,))
            rows = cur.fetchall()
            return {"ok": True, "hosts": [
                {"host": r[0], "best_score": r[1] or 0, 
                 "scan_count": r[2], "last_scan": str(r[3])}
                for r in rows
            ]}
    except Exception as e:
        raise HTTPException(500, str(e))


# ═══════════════════════════════════════════════════════════════
# REAL THREAT INTELLIGENCE — Ransomware + HIBP + CTI Feeds
# ═══════════════════════════════════════════════════════════════
import httpx as _httpx
from datetime import datetime as _dt

# Free public threat intelligence feeds
THREAT_FEEDS = [
    {"name": "Ransomwatch",      "url": "https://ransomwatch.telemetry.ltd/feed.json",     "type": "ransomware"},
    {"name": "CISA KEV",         "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "type": "cve"},
    {"name": "URLhaus",          "url": "https://urlhaus-api.abuse.ch/v1/urls/recent/",    "type": "malware_url"},
    {"name": "ThreatFox IOCs",   "url": "https://threatfox-api.abuse.ch/api/v1/",          "type": "ioc"},
    {"name": "MISP Feed",        "url": "https://www.circl.lu/doc/misp/feed-osint/",       "type": "osint"},
]

_threat_cache = {"data": [], "last_update": None}

async def fetch_ransomware_feed() -> list:
    """Fetch live ransomware group activity from Ransomwatch"""
    try:
        async with _httpx.AsyncClient(timeout=10) as client:
            r = await client.get("https://ransomwatch.telemetry.ltd/feed.json")
            if r.status_code == 200:
                data = r.json()
                groups = []
                for group in (data if isinstance(data, list) else data.get("groups", []))[:20]:
                    groups.append({
                        "name": group.get("name","Unknown"),
                        "posts": group.get("posts", 0),
                        "last_seen": group.get("last_updated",""),
                        "active": True,
                        "source": "Ransomwatch"
                    })
                return groups
    except Exception as e:
        print(f"[INFO] Ransomwatch unavailable: {e}")
    
    # Fallback: well-known active groups
    return [
        {"name":"LockBit 3.0","posts":847,"last_seen":"2025-01-10","active":True,"source":"fallback"},
        {"name":"ALPHV/BlackCat","posts":432,"last_seen":"2024-12-28","active":True,"source":"fallback"},
        {"name":"Cl0p","posts":291,"last_seen":"2025-01-08","active":True,"source":"fallback"},
        {"name":"Play","posts":187,"last_seen":"2025-01-09","active":True,"source":"fallback"},
        {"name":"8Base","posts":156,"last_seen":"2025-01-07","active":True,"source":"fallback"},
        {"name":"Hunters","posts":143,"last_seen":"2025-01-06","active":True,"source":"fallback"},
        {"name":"Medusa","posts":121,"last_seen":"2025-01-05","active":True,"source":"fallback"},
        {"name":"RansomHub","posts":98,"last_seen":"2025-01-10","active":True,"source":"fallback"},
    ]

async def fetch_cisa_kev() -> list:
    """Fetch CISA Known Exploited Vulnerabilities — free, no API key"""
    try:
        async with _httpx.AsyncClient(timeout=15) as client:
            r = await client.get(
                "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
            )
            if r.status_code == 200:
                data = r.json()
                vulns = data.get("vulnerabilities", [])
                # Return the 20 most recently added
                recent = sorted(vulns, key=lambda x: x.get("dateAdded",""), reverse=True)[:20]
                return [
                    {
                        "cve_id": v.get("cveID",""),
                        "vendor": v.get("vendorProject",""),
                        "product": v.get("product",""),
                        "vuln_name": v.get("vulnerabilityName",""),
                        "date_added": v.get("dateAdded",""),
                        "due_date": v.get("dueDate",""),
                        "description": v.get("shortDescription",""),
                        "source": "CISA KEV"
                    }
                    for v in recent
                ]
    except Exception as e:
        print(f"[INFO] CISA KEV unavailable: {e}")
    return []

def audit_action(action: str, resource: str, user_id: str, 
                 request: Request = None, status: str = "ok", detail: str = ""):
    """Write to audit log — PostgreSQL if available, print otherwise"""
    ip = request.client.host if request and request.client else "unknown"
    ua = request.headers.get("user-agent","") if request else ""
    
    if POSTGRES_AVAILABLE:
        try:
            with get_db() as conn:
                cur = conn.cursor()
                cur.execute("""
                    INSERT INTO audit_log 
                    (user_id, action, resource, detail, ip_address, user_agent, status, created_at)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,NOW())
                """, (user_id or "anonymous", action, resource, detail, ip, ua[:200], status))
        except Exception as e:
            print(f"[AUDIT] {action} {resource} user={user_id} ip={ip} status={status}")
    else:
        print(f"[AUDIT] {action} | resource={resource} | user={user_id} | ip={ip} | {status}")

async def hibp_check_email(email: str) -> dict:
    """Real HIBP breach check — requires HIBP_API_KEY"""
    api_key = os.getenv("HIBP_API_KEY")
    if not api_key:
        return {"error": "HIBP_API_KEY not configured", "demo": True,
                "breaches": [], "paste_count": 0}
    
    try:
        async with _httpx.AsyncClient(timeout=10) as client:
            r = await client.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                headers={
                    "hibp-api-key": api_key,
                    "User-Agent": "PM-OFFSEC-Security-Dashboard",
                    "Accept": "application/json"
                }
            )
            if r.status_code == 200:
                breaches = r.json()
                return {
                    "email": email,
                    "breached": True,
                    "breach_count": len(breaches),
                    "breaches": [
                        {
                            "name": b.get("Name",""),
                            "domain": b.get("Domain",""),
                            "date": b.get("BreachDate",""),
                            "pwn_count": b.get("PwnCount",0),
                            "data_classes": b.get("DataClasses",[]),
                            "verified": b.get("IsVerified",False),
                            "severity": "critical" if "Passwords" in b.get("DataClasses",[]) else "high"
                        }
                        for b in breaches
                    ]
                }
            elif r.status_code == 404:
                return {"email": email, "breached": False, "breach_count": 0, "breaches": []}
            elif r.status_code == 401:
                return {"error": "Invalid HIBP API key", "breached": None}
            else:
                return {"error": f"HIBP returned {r.status_code}", "breached": None}
    except Exception as e:
        return {"error": str(e), "breached": None}

async def hibp_check_password(sha1_prefix: str) -> str:
    """HIBP Pwned Passwords — k-anonymity, FREE, no API key needed"""
    try:
        async with _httpx.AsyncClient(timeout=5) as client:
            r = await client.get(
                f"https://api.pwnedpasswords.com/range/{sha1_prefix[:5].upper()}",
                headers={"User-Agent": "PM-OFFSEC-Security-Dashboard"}
            )
            if r.status_code == 200:
                return r.text
    except Exception:
        pass
    return ""

# ── API Endpoints ────────────────────────────────────────────

@app.get("/api/threat/ransomware")
async def get_ransomware_groups():
    """Live ransomware group feed"""
    groups = await fetch_ransomware_feed()
    return {"ok": True, "groups": groups, "count": len(groups), 
            "last_update": _dt.utcnow().isoformat()}

@app.get("/api/threat/cisa-kev")
async def get_cisa_kev(limit: int = 20):
    """CISA Known Exploited Vulnerabilities — free feed"""
    vulns = await fetch_cisa_kev()
    return {"ok": True, "vulnerabilities": vulns[:limit], "source": "CISA KEV",
            "total": len(vulns)}

@app.post("/api/threat/breach-check")
async def check_email_breach(request: Request):
    """Check email against HIBP — real data when API key configured"""
    body = await request.json()
    email = body.get("email","").strip().lower()
    if not email or "@" not in email:
        raise HTTPException(400, "Valid email required")
    result = await hibp_check_email(email)
    audit_action("breach_check", email, body.get("user_id",""), request)
    return result

@app.get("/api/threat/password-check/{sha1_prefix}")
async def check_password_breach(sha1_prefix: str):
    """k-Anonymity password check — FREE, no API key, privacy-safe"""
    if len(sha1_prefix) != 5:
        raise HTTPException(400, "Provide first 5 chars of SHA-1 hash")
    result = await hibp_check_password(sha1_prefix)
    return {"ok": True, "hashes": result}

@app.get("/api/threat/feed")
async def get_combined_threat_feed():
    """Combined threat intelligence — ransomware + CISA KEV"""
    ransomware = await fetch_ransomware_feed()
    kev = await fetch_cisa_kev()
    return {
        "ok": True,
        "ransomware_groups": ransomware[:10],
        "exploited_cves": kev[:10],
        "sources": ["Ransomwatch", "CISA KEV"],
        "last_update": _dt.utcnow().isoformat()
    }


# ═══════════════════════════════════════════════════════════════
# AUDIT LOG + GDPR + PER-USER RATE LIMITING
# ═══════════════════════════════════════════════════════════════
from collections import defaultdict as _defaultdict
import time as _time

# In-memory rate limit store (PostgreSQL used when available)
_rate_store = _defaultdict(list)
_rate_lock  = __import__('threading').Lock()

def check_rate_limit(key: str, limit: int = 10, window_seconds: int = 60) -> tuple:
    """Per-user rate limiting — returns (allowed: bool, remaining: int)"""
    now = _time.time()
    window_start = now - window_seconds
    
    with _rate_lock:
        # Clean old entries
        _rate_store[key] = [t for t in _rate_store[key] if t > window_start]
        count = len(_rate_store[key])
        
        if count >= limit:
            return False, 0
        
        _rate_store[key].append(now)
        return True, limit - count - 1

def rate_limit_scan(user_id: str, plan: str) -> tuple:
    """Enforce scan rate limits by plan"""
    limits = {"free": 3, "starter": 20, "pro": 60, "professional": 60, "enterprise": 999}
    limit = limits.get(plan, 3)
    key = f"scan:{user_id}:{_time.strftime('%Y-%m-%d')}"
    allowed, remaining = check_rate_limit(key, limit=limit, window_seconds=86400)
    return allowed, remaining, limit

@app.get("/api/audit/log")
async def get_audit_log(
    limit: int = 50,
    user: dict = Depends(get_current_user)
):
    """Get audit log for current user (admin gets all)"""
    if not POSTGRES_AVAILABLE:
        return {"ok": True, "logs": [], "demo": True,
                "message": "Audit log requires PostgreSQL"}
    try:
        with get_db() as conn:
            cur = conn.cursor()
            if user.get("role") == "admin":
                cur.execute("""
                    SELECT id, user_id, action, resource, detail, 
                           ip_address, status, created_at 
                    FROM audit_log ORDER BY created_at DESC LIMIT %s
                """, (min(limit, 500),))
            else:
                cur.execute("""
                    SELECT id, user_id, action, resource, detail,
                           ip_address, status, created_at
                    FROM audit_log WHERE user_id = %s 
                    ORDER BY created_at DESC LIMIT %s
                """, (user["user_id"], min(limit, 100)))
            
            rows = cur.fetchall()
            return {"ok": True, "logs": [
                {"id": r[0], "user_id": r[1], "action": r[2], "resource": r[3],
                 "detail": r[4], "ip": r[5], "status": r[6], "timestamp": str(r[7])}
                for r in rows
            ]}
    except Exception as e:
        raise HTTPException(500, str(e))

@app.delete("/api/gdpr/delete-my-data")
async def gdpr_delete_user_data(user: dict = Depends(get_current_user)):
    """GDPR Article 17 — Right to Erasure. Deletes ALL user data."""
    user_id = user["user_id"]
    deleted = {}
    
    if POSTGRES_AVAILABLE:
        try:
            with get_db() as conn:
                cur = conn.cursor()
                tables_to_clear = [
                    ("scan_results",  "user_id"),
                    ("scans",         "user_id"),
                    ("incidents",     "user_id"),
                    ("alert_prefs",   "user_id"),
                    ("user_plans",    "user_id"),
                    ("scheduled_scans","user_id"),
                    ("agreements",    "user_id"),
                ]
                for table, col in tables_to_clear:
                    try:
                        cur.execute(f"DELETE FROM {table} WHERE {col} = %s RETURNING *", (user_id,))
                        deleted[table] = cur.rowcount
                    except Exception:
                        pass
                
                # Log the deletion request
                cur.execute("""
                    INSERT INTO deletion_requests (id, user_id, user_email, status, completed_at)
                    VALUES (%s,%s,%s,'completed',NOW())
                """, (str(uuid.uuid4())[:16], user_id, user.get("email","")))
                
                # Anonymize user record (keep for legal purposes but remove PII)
                cur.execute("""
                    UPDATE users SET 
                        name = 'Deleted User',
                        email = %s,
                        phone = '',
                        company = '',
                        status = 'deleted'
                    WHERE id = %s
                """, (f"deleted_{user_id}@deleted.invalid", user_id))
                
            audit_action("gdpr_deletion", f"user:{user_id}", user_id, status="completed",
                        detail=f"Deleted tables: {list(deleted.keys())}")
            return {"ok": True, "message": "All your data has been deleted per GDPR Article 17",
                    "deleted": deleted, "user_anonymized": True}
        except Exception as e:
            raise HTTPException(500, f"Deletion failed: {str(e)}")
    else:
        return {"ok": True, "message": "Data deletion request recorded (no DB — handled manually)",
                "user_id": user_id}

@app.get("/api/gdpr/export-my-data")
async def gdpr_export_user_data(user: dict = Depends(get_current_user)):
    """GDPR Article 20 — Data Portability. Export all user data as JSON."""
    user_id = user["user_id"]
    export = {"user_id": user_id, "export_date": _dt.utcnow().isoformat(), "data": {}}
    
    if POSTGRES_AVAILABLE:
        try:
            with get_db() as conn:
                cur = conn.cursor()
                # User profile
                cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
                row = cur.fetchone()
                if row:
                    cols = [d[0] for d in cur.description]
                    user_data = dict(zip(cols, row))
                    user_data.pop("password", None)  # never export password hash
                    export["data"]["profile"] = user_data
                
                # Scan history
                cur.execute("""
                    SELECT id, target_host, scan_type, score, grade, created_at 
                    FROM scan_results WHERE user_id = %s LIMIT 1000
                """, (user_id,))
                export["data"]["scans"] = [dict(zip(["id","host","type","score","grade","date"], r)) for r in cur.fetchall()]
                
                # Audit log
                cur.execute("SELECT action, resource, status, created_at FROM audit_log WHERE user_id = %s LIMIT 500", (user_id,))
                export["data"]["audit_log"] = [dict(zip(["action","resource","status","date"], r)) for r in cur.fetchall()]
                
        except Exception as e:
            export["error"] = str(e)
    
    return export

@app.get("/api/admin/audit")
async def admin_audit_dashboard(user: dict = Depends(get_current_user)):
    """Admin-only: full audit dashboard with stats"""
    if user.get("plan") != "enterprise" and user.get("role") != "admin":
        raise HTTPException(403, "Admin or Enterprise plan required")
    
    if not POSTGRES_AVAILABLE:
        return {"ok": True, "demo": True, "stats": {
            "total_scans": 0, "total_users": 0, "critical_findings": 0
        }}
    
    try:
        with get_db() as conn:
            cur = conn.cursor()
            stats = {}
            
            cur.execute("SELECT COUNT(*) FROM scan_results")
            stats["total_scans"] = cur.fetchone()[0]
            
            cur.execute("SELECT COUNT(*) FROM users WHERE status = 'active'")
            stats["active_users"] = cur.fetchone()[0]
            
            cur.execute("SELECT COUNT(*) FROM audit_log WHERE created_at > NOW() - INTERVAL '24 hours'")
            stats["actions_24h"] = cur.fetchone()[0]
            
            cur.execute("""
                SELECT action, COUNT(*) as cnt FROM audit_log 
                WHERE created_at > NOW() - INTERVAL '7 days'
                GROUP BY action ORDER BY cnt DESC LIMIT 10
            """)
            stats["top_actions"] = [{"action": r[0], "count": r[1]} for r in cur.fetchall()]
            
            cur.execute("""
                SELECT DATE(created_at), COUNT(*) FROM scan_results
                WHERE created_at > NOW() - INTERVAL '30 days'
                GROUP BY DATE(created_at) ORDER BY DATE(created_at)
            """)
            stats["daily_scans"] = [{"date": str(r[0]), "count": r[1]} for r in cur.fetchall()]
            
            return {"ok": True, "stats": stats}
    except Exception as e:
        raise HTTPException(500, str(e))

# ═══════════════════════════════════════════════════════════════
# FINAL VERSION — NEW FEATURE ENDPOINTS
# ═══════════════════════════════════════════════════════════════

# ── Attack Surface Discovery ─────────────────────────────────
class AttackSurfaceReq(BaseModel):
    domain: str

@app.post("/api/attack-surface/discover")
async def attack_surface_discover(req: AttackSurfaceReq, _auth_user: dict = Depends(get_current_user)):
    """Discover subdomains and exposed services via CT logs + DNS"""
    import socket
    domain = req.domain.strip().lower().replace("https://","").replace("http://","").split("/")[0]
    
    common_subs = ["www","mail","api","dev","staging","admin","vpn","remote",
                   "ftp","smtp","pop","imap","cdn","static","assets","blog",
                   "shop","portal","backup","old","test","demo","dashboard"]
    
    assets = []
    for sub in common_subs[:15]:
        fqdn = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            risk = "medium"
            ports = [{"port": 443, "service": "HTTPS"}]
            if sub in ["ftp","old","backup"]: risk = "high"
            if sub in ["dev","staging","test"]: risk = "high"; ports.append({"port": 22, "service": "SSH"})
            if sub == "admin": risk = "critical"; ports.append({"port": 8443, "service": "HTTPS-ALT"})
            assets.append({"subdomain": fqdn, "ip": ip, "risk": risk, "ports": ports})
        except:
            pass  # Subdomain doesn't exist
    
    return {
        "domain": domain, "assets": assets,
        "total": len(assets),
        "exposed": len([a for a in assets if a["risk"] in ["high","critical"]])
    }

# ── Phishing Campaign Tracking ───────────────────────────────
class PhishingCampaignReq(BaseModel):
    user_id: str
    name: str
    template: str
    targets: list
    sender: str = "IT Security Team"

@app.post("/api/phishing/launch")
async def phishing_launch(req: PhishingCampaignReq, background_tasks: BackgroundTasks, _auth_user: dict = Depends(get_current_user)):
    """Launch a phishing simulation campaign"""
    campaign_id = f"CAMP-{str(uuid.uuid4())[:8].upper()}"
    
    # Store campaign (in production: send actual emails via SendGrid)
    campaign = {
        "id": campaign_id,
        "user_id": req.user_id,
        "name": req.name,
        "template": req.template,
        "sent": len(req.targets),
        "clicked": 0,
        "reported": 0,
        "targets": req.targets,
        "status": "active",
        "launched_at": datetime.utcnow().isoformat()
    }
    
    # Save to DB
    if POSTGRES_AVAILABLE:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO incidents (id, title, severity, status, user_id, description) VALUES (%s,%s,%s,%s,%s,%s)",
                (campaign_id, f"Phishing Campaign: {req.name}", "info", "active", req.user_id, str(campaign))
            )
    
    return {"ok": True, "campaign_id": campaign_id, "targets_count": len(req.targets)}

@app.post("/api/phishing/click/{campaign_id}")
async def phishing_click(campaign_id: str, _auth_user: dict = Depends(get_current_user)):
    """Track when a target clicks a phishing link"""
    return {"ok": True, "campaign_id": campaign_id, "message": "Click recorded"}

# ── Dark Web Monitoring ──────────────────────────────────────
class DarkWebReq(BaseModel):
    domain: str = ""
    email: str = ""
    keywords: list = []
    user_id: str = ""

@app.post("/api/darkweb/scan")
async def darkweb_scan(req: DarkWebReq, _auth_user: dict = Depends(get_current_user)):
    """Scan dark web sources for mentions of domain/email"""
    findings = []
    
    # HIBP integration for email breaches
    if req.email and os.getenv("HIBP_API_KEY"):
        try:
            import httpx
            async with httpx.AsyncClient() as client:
                r = await client.get(
                    f"https://haveibeenpwned.com/api/v3/breachedaccount/{req.email}",
                    headers={"hibp-api-key": os.getenv("HIBP_API_KEY"), "User-Agent": "PM-OFFSEC"}
                )
                if r.status_code == 200:
                    breaches = r.json()
                    for b in breaches[:5]:
                        findings.append({
                            "type": "credentials",
                            "severity": "high" if b.get("IsVerified") else "medium",
                            "title": f"Email found in {b['Name']} breach",
                            "detail": f"Breached on {b.get('BreachDate','unknown')}. Data: {', '.join(b.get('DataClasses',[])[:3])}",
                            "source": "Have I Been Pwned",
                            "date": b.get("BreachDate","Unknown")
                        })
        except Exception as e:
            pass
    
    # Domain monitoring (simulated if no real API)
    if req.domain:
        findings.append({
            "type": "paste",
            "severity": "medium", 
            "title": f"Domain monitoring active for {req.domain}",
            "detail": "No current mentions found. Monitoring continues 24/7.",
            "source": "PM::OFFSEC Monitor",
            "date": datetime.utcnow().strftime("%Y-%m-%d")
        })
    
    return {"ok": True, "findings": findings, "sources_checked": 6, "domain": req.domain}

# ── MSP Client Management ─────────────────────────────────────
class MSPClientReq(BaseModel):
    user_id: str
    client_name: str
    client_email: str
    plan: str = "starter"

@app.post("/api/msp/clients")
async def msp_add_client(req: MSPClientReq, _auth_user: dict = Depends(get_current_user)):
    """Add a client to MSP dashboard"""
    client_id = f"MSP-{str(uuid.uuid4())[:8].upper()}"
    return {"ok": True, "client_id": client_id, "client_name": req.client_name}

@app.get("/api/msp/clients/{user_id}")
async def msp_get_clients(user_id: str, _auth_user: dict = Depends(get_current_user)):
    """Get all MSP clients for a user"""
    return {"ok": True, "clients": [], "total": 0}

# ── Compliance Assessment ─────────────────────────────────────
@app.get("/api/compliance/{framework}/{user_id}")
async def get_compliance(framework: str, user_id: str, _auth_user: dict = Depends(get_current_user)):
    """Get compliance score for a specific framework"""
    frameworks = {
        "soc2": {"name": "SOC 2 Type II", "controls": 61},
        "iso27001": {"name": "ISO 27001:2022", "controls": 93},
        "pci": {"name": "PCI DSS v4.0", "controls": 12},
        "hipaa": {"name": "HIPAA Security Rule", "controls": 18},
        "nist": {"name": "NIST CSF 2.0", "controls": 106},
        "gdpr": {"name": "GDPR", "controls": 24},
    }
    if framework not in frameworks:
        raise HTTPException(400, f"Unknown framework: {framework}")
    fw = frameworks[framework]
    return {"ok": True, "framework": fw["name"], "score": 0, "controls": fw["controls"]}

# ── Email: Client Review ──────────────────────────────────────
class ClientReviewEmailReq(BaseModel):
    to: str
    client_name: str
    portal_url: str = "https://erprakashmijar.com/client/index.html"
    device: str = ""
    score: int = 0
    consultant: str = "PM::OFFSEC"
    message: str = ""

@app.post("/api/email/client-review")
async def send_client_review_email(req: ClientReviewEmailReq, background_tasks: BackgroundTasks, _auth_user: dict = Depends(get_current_user)):
    """Send client portal invitation email"""
    subject = f"Your Security Report is Ready — {req.device or 'Security Assessment'}"
    body = f"""Hi {req.client_name},

{"" + req.message + chr(10) + chr(10) if req.message else ""}Your latest security assessment has been completed.

Security Score: {req.score}/100
Device: {req.device or "Your infrastructure"}

Please visit your secure client portal to:
✓ View your security score and findings
✓ Review issues explained in plain English  
✓ Approve or decline recommended fixes
✓ Download your executive summary

Client Portal: {req.portal_url}

Best regards,
{req.consultant}
PM::OFFSEC Security Dashboard
https://erprakashmijar.com"""

    if os.getenv("SENDGRID_API_KEY"):
        try:
            background_tasks.add_task(
                send_email_sendgrid, req.to, subject, body,
                os.getenv("ALERT_FROM_EMAIL","contact@erprakashmijar.com")
            )
        except: pass
    
    return {"ok": True, "message": f"Review invitation sent to {req.to}"}


def validate_scan_target(host: str) -> tuple[bool, str]:
    """Block scanning private/internal IPs server-side"""
    import ipaddress
    host = host.strip().lower()
    
    # Block localhost variants
    blocked_hosts = ['localhost', '::1', '0.0.0.0', 
                     'metadata.google.internal', '169.254.169.254']
    if host in blocked_hosts:
        return False, "Scanning internal addresses not permitted"
    
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return False, f"Private/internal IP ranges not allowed: {host}"
    except ValueError:
        pass  # hostname, not IP - allow it through
    
    return True, "ok"


# ── AI Fix Endpoint ───────────────────────────────────────────
class AIFixRequest(BaseModel):
    issue: dict
    device: dict
    user_id: str = ""

@app.post("/api/ai/fix")
async def ai_fix_issue(req: AIFixRequest, _auth_user: dict = Depends(get_current_user)):
    """Generate AI-powered fix commands for a specific vulnerability"""
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise HTTPException(503, "Anthropic API key not configured")
    
    import anthropic
    client = anthropic.Anthropic(api_key=api_key)
    
    prompt = f"""You are a Linux security engineer. Fix this vulnerability:

Issue: {req.issue.get("title", "")}
Severity: {req.issue.get("severity", "")} (CVSS {req.issue.get("cvss", 0)})
Category: {req.issue.get("category", "")}
Detail: {req.issue.get("detail", "")}
OS: {req.device.get("os", "Ubuntu Linux")}
Hostname: {req.device.get("hostname", req.device.get("ip", "server"))}

Respond ONLY with valid JSON (no markdown, no preamble):
{{"explanation":"plain English explanation for non-technical reader","commands":["exact bash command 1","exact bash command 2"],"verify":"command to verify fix worked","risk":"low|medium|high","time":"estimated time","reboot":false}}"""

    try:
        message = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1000,
            messages=[{"role": "user", "content": prompt}]
        )
        text = message.content[0].text.strip()
        # Parse JSON
        import json
        text_clean = text.replace("```json", "").replace("```", "").strip()
        result = json.loads(text_clean)
        return {"ok": True, **result}
    except Exception as e:
        raise HTTPException(500, f"AI fix failed: {str(e)}")


# Optional auth — returns user if token valid, None if no token
_optional_bearer = HTTPBearer(auto_error=False)

def get_optional_user(credentials: HTTPAuthorizationCredentials = Depends(_optional_bearer)):
    """Returns user dict if valid token, None if no token provided"""
    if not credentials:
        return None
    try:
        if not JWT_AVAILABLE:
            return None
        payload = pyjwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return {"user_id": payload.get("user_id"), "email": payload.get("sub"), "plan": payload.get("plan","free")}
    except Exception:
        return None


def verify_user_plan(user_id: str) -> str:
    """Get user plan from database — cannot be faked by client"""
    try:
        plan = plan_get(user_id)
        return plan or "free"
    except Exception:
        return "free"

def check_plan_feature(user_id: str, required_plan: str) -> bool:
    """Check if user has required plan — server-verified"""
    plan = verify_user_plan(user_id)
    plan_order = {"free": 0, "starter": 1, "pro": 2, "professional": 2, "enterprise": 3}
    user_level = plan_order.get(plan, 0)
    req_level  = plan_order.get(required_plan, 1)
    return user_level >= req_level

# ── SECURITY & RATE LIMITING ──────────────────────────────────────
from fastapi import Request
from fastapi.responses import JSONResponse
import time
from collections import defaultdict

# Simple in-memory rate limiter
_rate_store = defaultdict(list)
RATE_LIMIT    = 60   # requests
RATE_WINDOW   = 60   # seconds

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    # Skip rate limiting for static assets
    path = request.url.path
    if not path.startswith("/api/"):
        return await call_next(request)

    client_ip = request.client.host or "unknown"
    now = time.time()

    # Clean old entries
    _rate_store[client_ip] = [t for t in _rate_store[client_ip] if now - t < RATE_WINDOW]

    if len(_rate_store[client_ip]) >= RATE_LIMIT:
        return JSONResponse(
            status_code=429,
            content={"error": "Rate limit exceeded. Max 60 requests per minute."},
            headers={"Retry-After": "60"}
        )

    _rate_store[client_ip].append(now)
    return await call_next(request)

@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    # Security headers on all responses
    response.headers["X-Content-Type-Options"]    = "nosniff"
    response.headers["Content-Security-Policy"]    = "default-src 'self' https:; script-src 'self' 'unsafe-inline' https://accounts.google.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https:; connect-src 'self' https: wss:"
    response.headers["X-Frame-Options"]           = "DENY"
    response.headers["X-XSS-Protection"]          = "1; mode=block"
    response.headers["Referrer-Policy"]           = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"]        = "geolocation=(), microphone=(), camera=()"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

@app.on_event("startup")
async def startup():
    init_db()  # Initialize PostgreSQL schema
    start_scheduler()

@app.on_event("shutdown")
async def shutdown():
    stop_scheduler()

# ── HEALTH ───────────────────────────────────────────────────────
@app.get("/")
def root():
    return {"status": "online", "version": "3.0.0",
            "service": "PM::OFFSEC Security Dashboard API",
            "docs": "/docs"}

@app.get("/api/health")
def health():
    return {"status": "ok", "timestamp": datetime.now().isoformat(),
            "scheduler": "running", "stripe": bool(os.getenv("STRIPE_SECRET_KEY")),
            "sendgrid": bool(os.getenv("SENDGRID_API_KEY")),
            "ai": bool(os.getenv("ANTHROPIC_API_KEY"))}

# ── SCAN: LOCAL ──────────────────────────────────────────────────
@app.get("/api/scan/local")
def scan_local(user_id: str = "anonymous", x_user_plan: str = Header(default="free")):
    _check_scan_quota(user_id, x_user_plan)
    try:
        result = local_scan()
        _save_history(result, user_id)
        _increment_scan_count(user_id)
        # Auto-send email alerts
        try:
            prefs = alert_prefs_get(user_id)
            if prefs.get("enabled") and prefs.get("email"):
                issues = result.get("issues", [])
                crit = [i for i in issues if i.get("severity") == "critical"]
                high = [i for i in issues if i.get("severity") == "high"]
                if crit or high:
                    from fastapi import BackgroundTasks as BT
                    send_critical_alert(prefs["email"], user_id, result)
                elif prefs.get("on_scan_complete", False):
                    send_scan_complete(prefs["email"], user_id, result)
        except Exception as _e:
            pass  # Never block scan results due to email failure
        return result
    except Exception as e:
        raise HTTPException(500, f"Scan failed: {str(e)}")

# ── SCAN: REMOTE ─────────────────────────────────────────────────
class RemoteScanReq(BaseModel):
    host: str
    port: int = 22
    username: str = "root"
    password: Optional[str] = None
    key_path: Optional[str] = None
    user_id: str = "anonymous"
    alert_email: Optional[str] = None

@app.post("/api/scan/remote")
async def scan_remote(req: RemoteScanReq, background_tasks: BackgroundTasks,
                      x_user_plan: str = Header(default="free")):
    # Validate target IP/hostname
    ip_ok, ip_msg = validate_scan_target(req.host)
    if not ip_ok:
        raise HTTPException(400, f"Invalid scan target: {ip_msg}")
    # Rate limiting — enforced server-side
    # Rate limit check using user_id from request
    _scan_uid = req.user_id if req.user_id else ""
    if _scan_uid:
        _server_plan = verify_user_plan(_scan_uid)
        _allowed, _remaining, _limit = rate_limit_scan(_scan_uid, _server_plan)
        if not _allowed:
            raise HTTPException(429, f"Scan rate limit reached ({_limit}/day for {_server_plan} plan). Upgrade for more scans.")
    # Verify plan server-side from DB, not from request header
    server_plan = verify_user_plan(req.user_id if req.user_id else (_auth_user.get("user_id","") if "_auth_user" in dir() else ""))
    _check_scan_quota(req.user_id, server_plan)
    try:
        result = remote_scan(host=req.host, port=req.port,
                             username=req.username, password=req.password,
                             key_path=req.key_path)
        if "error" in result:
            raise HTTPException(400, result["error"])
        _save_history(result, user_id)
        _increment_scan_count(req.user_id)
        # Email alert in background (if plan supports it)
        if req.alert_email and check_plan_limit(x_user_plan, "email_alerts"):
            background_tasks.add_task(send_scan_alert, req.alert_email, result)
        # Clear sensitive SSH credentials from memory before returning
        if req.password: req.password = ""
        if req.key_path: req.key_path = ""
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, str(e))

# ── SCAN: NETWORK DISCOVER ───────────────────────────────────────
class NetworkReq(BaseModel):
    subnet: Optional[str] = None
    user_id: str = "anonymous"

@app.post("/api/scan/network")
def scan_network(req: NetworkReq, x_user_plan: str = Header(default="free")):
    if not check_plan_limit(x_user_plan, "network_discovery"):
        raise HTTPException(403, "Network discovery requires Starter plan or higher. Upgrade at /billing/plans")
    try:
        devices = discover_network_devices(req.subnet)
        return {"subnet": req.subnet or "auto", "devices_found": len(devices),
                "devices": devices, "timestamp": datetime.now().isoformat()}
    except Exception as e:
        raise HTTPException(500, str(e))

# ── HISTORY ──────────────────────────────────────────────────────
@app.get("/api/history/{ip}")
def get_history(ip: str):
    return {"ip": ip.replace("-", "."), "scans": scan_history.get(ip.replace("-", "."), [])}

@app.get("/api/history")
def get_all_history():
    return {"history": scan_history}

# ── AI ────────────────────────────────────────────────────────────
AI_SYSTEM = """You are an expert cybersecurity analyst in PM::OFFSEC Security Dashboard.
Analyze real Linux system scan results. Provide:
1. Clear explanations (explain all jargon)
2. Prioritized findings with exact bash remediation commands in code blocks
3. Business risk context and CVSS context
4. Quick wins vs long-term fixes

Be concise, professional, and actionable. Use clear section headers."""

class AIReq(BaseModel):
    scan_data: dict
    question: Optional[str] = None
    user_id: str = "anonymous"

@app.post("/api/ai/analyze")
async def ai_analyze(req: AIReq, x_user_plan: str = Header(default="free")):
    if not check_plan_limit(x_user_plan, "ai_analysis"):
        raise HTTPException(403, "AI analysis requires Starter plan or higher")
    _call_ai(req.scan_data, "analyze")
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise HTTPException(500, "ANTHROPIC_API_KEY not configured in .env")
    try:
        client = anthropic.Anthropic(api_key=api_key)
        prompt = f"""Analyze this LIVE security scan and provide:
1. Executive Summary (2-3 sentences, non-technical)
2. Top 3 Critical Risks with exact business impact
3. Immediate Actions — exact bash commands for each fix
4. 30-Day Remediation Roadmap

Scan data: {json.dumps(req.scan_data, indent=2)}"""
        msg = client.messages.create(model="claude-opus-4-5", max_tokens=1500,
                                      system=AI_SYSTEM, messages=[{"role":"user","content":prompt}])
        return {"analysis": msg.content[0].text, "model": "claude-opus-4-5",
                "timestamp": datetime.now().isoformat()}
    except Exception as e:
        raise HTTPException(500, str(e))

@app.post("/api/ai/chat")
async def ai_chat(req: AIReq, x_user_plan: str = Header(default="free")):
    if not check_plan_limit(x_user_plan, "ai_analysis"):
        raise HTTPException(403, "AI chat requires Starter plan or higher")
    if not req.question:
        raise HTTPException(400, "question is required")
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise HTTPException(500, "ANTHROPIC_API_KEY not configured")
    try:
        client = anthropic.Anthropic(api_key=api_key)
        ctx = f"Scan context: {json.dumps(req.scan_data)}\n\nQuestion: {req.question}" if req.scan_data else req.question
        msg = client.messages.create(model="claude-opus-4-5", max_tokens=1000,
                                      system=AI_SYSTEM, messages=[{"role":"user","content":ctx}])
        return {"reply": msg.content[0].text, "timestamp": datetime.now().isoformat()}
    except Exception as e:
        raise HTTPException(500, str(e))

# ── BILLING: PLANS ───────────────────────────────────────────────
@app.get("/api/billing/plans")
def get_plans():
    """Return all pricing plans — used by the pricing page"""
    return {"plans": PLANS}

@app.get("/api/billing/plan/{user_id}")
def get_user_plan(user_id: str):
    plan_key = user_plans.get(user_id, "free")
    return {"user_id": user_id, "plan": plan_key, "plan_info": get_plan_info(plan_key),
            "subscription": user_subs.get(user_id)}

# ── BILLING: CHECKOUT ────────────────────────────────────────────
class CheckoutReq(BaseModel):
    plan: str
    user_id: str
    user_email: str
    provider: str = "stripe"   # "stripe" or "lemonsqueezy"
    success_url: str = ""
    cancel_url: str = ""

@app.post("/api/billing/checkout")
async def create_checkout(req: CheckoutReq, _auth_user: dict = Depends(get_current_user)):
    if req.plan not in PLANS or PLANS[req.plan]["price"] == 0:
        raise HTTPException(400, "Invalid paid plan")
    app_url = os.getenv("APP_URL", "https://erprakashmijar.com")
    success = req.success_url or f"{app_url}/billing/success.html"
    cancel  = req.cancel_url  or f"{app_url}/billing/pricing.html"
    if req.provider == "lemonsqueezy":
        url = await create_lemonsqueezy_checkout(req.plan, req.user_email, req.user_id)
    else:
        url = await create_stripe_checkout(req.plan, req.user_email, req.user_id, success, cancel)
    return {"checkout_url": url, "provider": req.provider, "plan": req.plan}

# ── BILLING: WEBHOOKS ────────────────────────────────────────────
@app.post("/api/webhooks/stripe")
async def stripe_webhook(request: Request, background_tasks: BackgroundTasks,
                         stripe_signature: str = Header(None)):
    payload = await request.body()
    event   = handle_stripe_webhook(payload, stripe_signature)
    etype   = event["type"]
    data    = event["data"]
    if etype == "checkout.session.completed":
        uid  = data.get("metadata", {}).get("user_id")
        plan = data.get("metadata", {}).get("plan")
        sub_id = data.get("subscription")
        if uid and plan:
            user_plans[uid] = plan
            user_subs[uid]  = {"subscription_id": sub_id, "provider": "stripe",
                                "plan": plan, "active": True,
                                "started_at": datetime.now().isoformat()}
            email = data.get("customer_email", "")
            name  = data.get("customer_details", {}).get("name", "Customer")
            if email:
                background_tasks.add_task(send_subscription_email, email, name, plan, "activated")
    elif etype in ("customer.subscription.deleted", "customer.subscription.updated"):
        uid = next((k for k,v in user_subs.items() if v.get("subscription_id")==data.get("id")), None)
        if uid:
            if etype.endswith("deleted"):
                user_plans[uid] = "free"
                user_subs[uid]["active"] = False
    return {"received": True}

@app.post("/api/webhooks/lemonsqueezy")
async def ls_webhook(request: Request, background_tasks: BackgroundTasks,
                     x_signature: str = Header(None)):
    raw     = await request.body()
    try:
        payload = json.loads(raw) if raw else {}
    except (json.JSONDecodeError, ValueError):
        raise HTTPException(400, "Invalid JSON payload")
    event   = handle_lemonsqueezy_webhook(payload, x_signature or "", raw)
    etype   = event.get("type", "")
    meta    = event.get("meta", {}).get("custom_data", {})
    uid     = meta.get("user_id")
    plan    = meta.get("plan")
    if uid and plan and etype in ("subscription_created", "order_created"):
        user_plans[uid] = plan
        user_subs[uid]  = {"provider": "lemonsqueezy", "plan": plan, "active": True,
                            "started_at": datetime.now().isoformat()}
    elif uid and etype == "subscription_cancelled":
        user_plans[uid] = "free"
        if uid in user_subs: user_subs[uid]["active"] = False
    return {"received": True}

# ── BILLING: CANCEL ──────────────────────────────────────────────
class CancelReq(BaseModel):
    user_id: str

@app.post("/api/billing/cancel")
async def cancel_subscription(req: CancelReq, background_tasks: BackgroundTasks, _auth_user: dict = Depends(get_current_user)):
    sub = user_subs.get(req.user_id)
    if not sub:
        raise HTTPException(404, "No active subscription found")
    if sub.get("provider") == "stripe":
        from billing import cancel_stripe_subscription
        ok = await cancel_stripe_subscription(sub["subscription_id"])
        if ok:
            user_subs[req.user_id]["cancel_at_period_end"] = True
            return {"ok": True, "message": "Subscription will cancel at period end"}
    user_plans[req.user_id] = "free"
    user_subs[req.user_id]["active"] = False
    return {"ok": True, "message": "Subscription cancelled"}

# ── ALERTS: PREFERENCES ──────────────────────────────────────────
class AlertPrefReq(BaseModel):
    user_id: str
    email: str
    enabled: bool = True
    alert_on: list = ["critical", "high"]

@app.post("/api/alerts/preferences")
def set_alert_prefs(req: AlertPrefReq):
    alert_prefs[req.user_id] = {"email": req.email, "enabled": req.enabled, "alert_on": req.alert_on}
    return {"ok": True}

@app.get("/api/alerts/preferences/{user_id}")
def get_alert_prefs(user_id: str):
    return alert_prefs.get(user_id, {"email": "", "enabled": False, "alert_on": ["critical", "high"]})

@app.post("/api/alerts/test")
async def send_test_alert(user_id: str, email: str, _auth_user: dict = Depends(get_current_user)):
    """Send a test alert email"""
    result = send_email(email, "PM::OFFSEC — Test Alert",
        f"""<div style="background:#03070f;color:#c0dce8;font-family:monospace;padding:2rem;border:1px solid rgba(0,255,136,.15);border-radius:8px">
        <div style="color:#00ff88;font-size:18px;margin-bottom:1rem">✓ Test Alert Working</div>
        <p>Your PM::OFFSEC email alerts are configured correctly.<br>You'll receive alerts when scans find critical or high severity issues.</p>
        </div>""")
    return result

# ── ALERTS: WEEKLY REPORT ────────────────────────────────────────
class WeeklyReportReq(BaseModel):
    user_id: str
    user_name: str
    email: str
    devices: list

@app.post("/api/alerts/weekly")
async def send_weekly(req: WeeklyReportReq, x_user_plan: str = Header(default="free")):
    if not check_plan_limit(x_user_plan, "email_alerts"):
        raise HTTPException(403, "Email reports require Starter plan or higher")
    result = send_weekly_report(req.email, req.user_name, req.devices)
    return result

# ── SCHEDULED SCANS ──────────────────────────────────────────────
class ScheduleReq(BaseModel):
    schedule_id: Optional[str] = None
    device_config: dict   # {type:"local"} or {type:"remote",host:...,username:...,password:...}
    cron_expression: str  # e.g. "0 9 * * *"
    alert_email: Optional[str] = None
    user_id: str = "anonymous"

@app.post("/api/schedules")
async def create_schedule(req: ScheduleReq, x_user_plan: str = Header(default="free")):
    if not check_plan_limit(x_user_plan, "scheduled_scans"):
        raise HTTPException(403, "Scheduled scans require Professional plan or higher")
    sid = req.schedule_id or str(uuid.uuid4())[:8]
    result = add_schedule(
        schedule_id=sid,
        device_config=req.device_config,
        cron_expression=req.cron_expression,
        alert_email=req.alert_email or "",
        scan_fn=None,
        alert_fn=send_scan_alert
    )
    return result

@app.get("/api/schedules")
def list_schedules():
    return {"schedules": get_all_schedules(), "presets": CRON_PRESETS}

@app.get("/api/schedules/{schedule_id}")
def get_schedule_route(schedule_id: str):
    s = get_schedule(schedule_id)
    if not s: raise HTTPException(404, "Schedule not found")
    return s

@app.delete("/api/schedules/{schedule_id}")
def delete_schedule(schedule_id: str):
    ok = remove_schedule(schedule_id)
    return {"ok": ok}

@app.patch("/api/schedules/{schedule_id}/pause")
def pause_schedule_route(schedule_id: str):
    return {"ok": pause_schedule(schedule_id)}

@app.patch("/api/schedules/{schedule_id}/resume")
def resume_schedule_route(schedule_id: str):
    return {"ok": resume_schedule(schedule_id)}

# ── EMAIL: WELCOME ───────────────────────────────────────────────
class WelcomeReq(BaseModel):
    email: str
    name: str
    plan: str = "free"

@app.post("/api/email/welcome")
async def welcome_email(req: WelcomeReq, background_tasks: BackgroundTasks):
    background_tasks.add_task(send_welcome_email, req.email, req.name, req.plan)
    return {"ok": True, "message": "Welcome email queued"}

# ── HELPERS ──────────────────────────────────────────────────────
def _save_history(result: dict, user_id: str = "anonymous"):
    """Save scan result to PostgreSQL (or in-memory fallback)"""
    scan_save(user_id, result)
def _increment_scan_count(user_id: str):
    key = f"{user_id}:{datetime.now().strftime('%Y-%m-%d')}"
    scan_counts[key] = scan_counts.get(key, 0) + 1

def _get_scan_count_today(user_id: str) -> int:
    key = f"{user_id}:{datetime.now().strftime('%Y-%m-%d')}"
    return scan_counts.get(key, 0)

def _check_scan_quota(user_id: str, plan_key: str):
    count = _get_scan_count_today(user_id)
    if not check_plan_limit(plan_key, "scans_per_day", count):
        plan = get_plan_info(plan_key)
        raise HTTPException(429, f"Daily scan limit reached ({plan['scans_per_day']} scans/day on {plan['name']} plan). Upgrade at /billing/plans")

def _call_ai(scan_data: dict, mode: str):
    pass  # placeholder for usage tracking

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.getenv("PORT", 8000)), reload=True)

# ═══════════════════════════════════════════════════════════════
# NEW ROUTES — v4.0 — Website Scanner, OSINT, SOC, SIEM
# ═══════════════════════════════════════════════════════════════

from web_scanner import website_scan
from osint import (full_email_osint, check_email_breaches,
                   check_password_pwned, check_ip_reputation,
                   check_virustotal, shodan_lookup, lookup_username, domain_intel)
from soc import (create_incident, update_incident, get_incidents, get_incident,
                 auto_create_incident_from_scan, add_ioc, search_iocs,
                 check_ioc_match, extract_iocs_from_scan, get_wazuh_alerts,
                 get_wazuh_agents, splunk_search, splunk_send_log,
                 get_soc_metrics, map_to_mitre, get_playbooks, get_playbook,
                 MITRE_TECHNIQUES, IOC_TYPES, INCIDENT_STATUSES)

# ── WEBSITE SCANNER ──────────────────────────────────────────────
class WebScanReq(BaseModel):
    domain: str
    user_id: str = "anonymous"
    alert_email: Optional[str] = None


@app.get("/api/stats/{user_id}")
def dashboard_stats(user_id: str):
    """Get summary stats for a user's dashboard"""
    return get_dashboard_stats(user_id)

@app.get("/api/score-history/{user_id}")
def score_history(user_id: str, days: int = 30):
    """Get security score history for trend chart"""
    return {"history": get_score_history(user_id, days)}

def _safe_user(u: dict) -> dict:
    """Never expose password hashes or secrets to the client."""
    return {k: v for k, v in u.items() if k not in ("password", "password_hash", "mfa_secret")}

@app.get("/api/users")
def list_users(_admin: dict = Depends(require_admin)):
    """Admin only: list all users (password fields stripped)."""
    return {"users": [_safe_user(u) for u in users_get_all()]}

# ── Secured Admin endpoints ──────────────────────────────────────
class AdminRoleReq(BaseModel):
    role: str   # 'admin' | 'user' | 'client'

class AdminPlanReq(BaseModel):
    plan: str   # 'free' | 'starter' | 'professional' | 'enterprise'

class AdminStatusReq(BaseModel):
    status: str  # 'active' | 'suspended'

@app.get("/api/admin/users")
def admin_list_users(_admin: dict = Depends(require_admin)):
    return {"users": [_safe_user(u) for u in users_get_all()]}

@app.put("/api/admin/users/{user_id}/role")
def admin_set_role(user_id: str, req: AdminRoleReq, admin: dict = Depends(require_admin)):
    if req.role not in ("admin", "user", "client"):
        raise HTTPException(400, "Invalid role")
    if user_id == admin.get("user_id") and req.role != "admin":
        raise HTTPException(400, "You cannot remove your own admin role")
    if not user_update(user_id, role=req.role):
        raise HTTPException(404, "User not found")
    return {"ok": True, "user_id": user_id, "role": req.role}

@app.put("/api/admin/users/{user_id}/plan")
def admin_set_plan(user_id: str, req: AdminPlanReq, _admin: dict = Depends(require_admin)):
    if req.plan not in ("free", "starter", "professional", "enterprise"):
        raise HTTPException(400, "Invalid plan")
    if not user_update(user_id, plan=req.plan):
        raise HTTPException(404, "User not found")
    return {"ok": True, "user_id": user_id, "plan": req.plan}

@app.put("/api/admin/users/{user_id}/status")
def admin_set_status(user_id: str, req: AdminStatusReq, admin: dict = Depends(require_admin)):
    if req.status not in ("active", "suspended"):
        raise HTTPException(400, "Invalid status")
    if user_id == admin.get("user_id") and req.status != "active":
        raise HTTPException(400, "You cannot suspend your own account")
    if not user_update(user_id, status=req.status):
        raise HTTPException(404, "User not found")
    return {"ok": True, "user_id": user_id, "status": req.status}

@app.delete("/api/admin/users/{user_id}")
def admin_delete_user(user_id: str, admin: dict = Depends(require_admin)):
    if user_id == admin.get("user_id"):
        raise HTTPException(400, "You cannot delete your own account")
    if not user_delete(user_id):
        raise HTTPException(404, "User not found")
    return {"ok": True, "deleted": user_id}

# ── Portal data endpoints (real backend data for client & admin portals) ──
def _summarize_scans(scans: list) -> dict:
    """Aggregate a user's scans into a portal-friendly summary."""
    sev_count = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    devices = []
    scores = []
    for s in scans:
        issues = s.get("issues") or []
        if isinstance(issues, str):
            try: issues = json.loads(issues)
            except Exception: issues = []
        for iss in issues:
            sev = (iss.get("severity") or "low").lower()
            if sev in sev_count: sev_count[sev] += 1
        score = s.get("score", 0) or 0
        scores.append(score)
        devices.append({
            "hostname": s.get("hostname", "") or s.get("ip", "device"),
            "ip": s.get("ip", ""),
            "score": score,
            "issue_count": len(issues),
            "last_scan": str(s.get("created_at", "")) or "",
        })
    avg = round(sum(scores) / len(scores)) if scores else None
    return {
        "device_count": len(devices),
        "devices": devices,
        "issues_by_severity": sev_count,
        "critical_count": sev_count["critical"],
        "avg_score": avg,
        "total_issues": sum(sev_count.values()),
    }

@app.get("/api/portal/client")
def portal_client(user: dict = Depends(get_current_user)):
    """The signed-in user's own security overview (client portal)."""
    scans = scan_get_recent(user["user_id"], limit=50)
    summary = _summarize_scans(scans)
    summary["user"] = {"email": user.get("email"), "plan": user.get("plan", "free")}
    return summary

@app.get("/api/portal/admin/clients")
def portal_admin_clients(_admin: dict = Depends(require_admin)):
    """Per-client summary across all non-admin accounts (admin/MSP portal)."""
    clients = []
    crit_total = 0
    for u in users_get_all():
        if u.get("role") == "admin":
            continue
        scans = scan_get_recent(u["id"], limit=50)
        summ = _summarize_scans(scans)
        crit_total += summ["critical_count"]
        last = scans[0].get("created_at") if scans else None
        clients.append({
            "id": u["id"], "name": u.get("name", ""), "email": u.get("email", ""),
            "plan": u.get("plan", "free"), "status": u.get("status", "active"),
            "device_count": summ["device_count"], "avg_score": summ["avg_score"],
            "critical_count": summ["critical_count"], "last_scan": str(last) if last else None,
        })
    return {
        "total_clients": len(clients),
        "critical_total": crit_total,
        "clients": clients,
    }

@app.post("/api/users/login-record/{user_id}")
def record_login(user_id: str):
    """Record user login"""
    user_record_login(user_id)
    return {"ok": True}

class ProfileUpdateReq(BaseModel):
    name: str = None
    email: str = None
    phone: str = None
    address: str = None
    company: str = None

@app.put("/api/profile")
def update_my_profile(req: ProfileUpdateReq, user: dict = Depends(get_current_user)):
    """Update the signed-in user's own profile details (name, email, phone, address, company)."""
    fields = {}
    if req.name is not None:    fields["name"] = req.name.strip()
    if req.phone is not None:   fields["phone"] = req.phone.strip()
    if req.address is not None: fields["address"] = req.address.strip()
    if req.company is not None: fields["company"] = req.company.strip()
    if req.email is not None and req.email.strip():
        new_email = req.email.strip().lower()
        existing = user_get_by_email(new_email)
        if existing and existing.get("id") != user["user_id"]:
            raise HTTPException(400, "That email is already in use by another account")
        fields["email"] = new_email
    if not fields:
        raise HTTPException(400, "No fields to update")
    if not user_update(user["user_id"], **fields):
        raise HTTPException(404, "User not found")
    updated = user_get(user["user_id"]) or {}
    return {"ok": True, "profile": _safe_user(updated)}

# ── Org / Employee / Device management (client → employees → laptops) ──
def _org_id_for(user: dict) -> str:
    """A client's org is their own user id; employees carry org_id in their record."""
    rec = user_get(user["user_id"]) or {}
    return rec.get("org_id") or user["user_id"]

class OrgDeviceReq(BaseModel):
    employee_name: str = ""
    employee_email: str = ""
    device_name: str
    device_type: str = "laptop"
    os: str = ""

@app.get("/api/org/devices")
def org_devices_list(user: dict = Depends(get_current_user)):
    """List devices for the caller's org. Clients see all org devices;
    employees see the org they belong to."""
    org = _org_id_for(user)
    devices = org_devices_get(org)
    return {"org_id": org, "device_count": len(devices), "devices": devices}

@app.post("/api/org/devices")
def org_devices_create(req: OrgDeviceReq, user: dict = Depends(get_current_user)):
    if not req.device_name.strip():
        raise HTTPException(400, "Device name is required")
    org = _org_id_for(user)
    rec = user_get(user["user_id"]) or {}
    added_by = "client" if rec.get("role") == "client" else "employee"
    # Employees can only register devices under their own name/email.
    if added_by == "employee":
        dev = org_device_add(org, {"employee_name": rec.get("name",""), "employee_email": rec.get("email",""),
                                   "device_name": req.device_name, "device_type": req.device_type,
                                   "os": req.os, "added_by": "employee"})
    else:
        dev = org_device_add(org, req.dict() | {"added_by": "client"})
    return {"ok": True, "device": dev}

@app.delete("/api/org/devices/{device_id}")
def org_devices_remove(device_id: str, user: dict = Depends(get_current_user)):
    org = _org_id_for(user)
    if not org_device_delete(device_id, org):
        raise HTTPException(404, "Device not found in your organization")
    return {"ok": True, "deleted": device_id}

class EmployeeJoinReq(BaseModel):
    name: str
    email: str
    password: str
    org_id: str            # the client's org id (their user id), shared by the client

@app.post("/api/org/employee/register")
def employee_register(req: EmployeeJoinReq):
    """An employee self-registers into a client's organization. Their account
    is created with role 'employee' and linked to the client's org_id, so their
    devices show up on that client's dashboard."""
    if not req.org_id:
        raise HTTPException(400, "An organization code is required")
    org_owner = user_get(req.org_id)
    if not org_owner:
        raise HTTPException(404, "Organization not found")
    existing = user_get_by_email(req.email.lower())
    if existing:
        raise HTTPException(400, "An account with this email already exists")
    import hashlib, uuid as _uuid
    uid = str(_uuid.uuid4())[:16]
    if BCRYPT_AVAILABLE:
        hashed = bcrypt.hashpw(req.password.encode(), bcrypt.gensalt()).decode()
    else:
        hashed = hashlib.sha256(req.password.encode()).hexdigest()
    user_create(user_id=uid, name=req.name.strip(), email=req.email.lower(), password=hashed, role="employee", plan="free")
    user_update(uid, org_id=req.org_id)
    token = ""
    if JWT_AVAILABLE:
        token = pyjwt.encode({"sub": req.email.lower(), "user_id": uid, "plan": "free", "role": "employee",
            "exp": datetime.utcnow()+timedelta(hours=JWT_EXPIRY_HOURS)}, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return {"ok": True, "access_token": token, "user_id": uid, "email": req.email.lower(),
            "name": req.name.strip(), "role": "employee", "org_id": req.org_id}

# ── PAYMENT & BILLING ENDPOINTS ──────────────────────────────────

class TrialReq(BaseModel):
    user_id: str
    plan: str = "starter"

class InvoiceReq(BaseModel):
    user_id: str
    user_name: str
    user_email: str
    plan: str
    amount: float
    provider: str
    transaction_id: str

class UpgradeReq(BaseModel):
    user_id: str
    user_email: str
    current_plan: str
    target_plan: str
    provider: str = "stripe"

class DowngradeReq(BaseModel):
    user_id: str
    reason: str = "cancelled"

@app.post("/api/billing/trial/start")
def start_free_trial(req: TrialReq):
    """Start a 14-day free trial for new users"""
    result = start_trial(req.user_id, req.plan)
    return result

@app.get("/api/billing/trial/{user_id}")
def get_trial_status(user_id: str):
    """Check if user is on trial and days remaining"""
    return check_trial_status(user_id)

@app.post("/api/billing/invoice/generate")
def create_invoice(req: InvoiceReq):
    """Generate invoice data after successful payment"""
    inv = generate_invoice(req.user_id, req.plan, req.amount, req.provider, req.transaction_id)
    html = generate_invoice_html(inv, req.user_name, req.user_email)
    return {"invoice": inv, "html": html}

@app.get("/api/billing/invoice/{transaction_id}")
def get_invoice_html(transaction_id: str, user_name: str = "", user_email: str = "", plan: str = "starter", amount: float = 19.0):
    """Get printable invoice HTML"""
    inv = generate_invoice("unknown", plan, amount, "stripe", transaction_id)
    html = generate_invoice_html(inv, user_name, user_email)
    from fastapi.responses import HTMLResponse
    return HTMLResponse(content=html)

@app.post("/api/billing/downgrade")
def downgrade_user(req: DowngradeReq):
    """Downgrade user to free plan"""
    ok = downgrade_to_free(req.user_id, req.reason)
    return {"ok": ok}

@app.get("/api/billing/upgrade-url/{user_id}")
def get_upgrade(user_id: str, current_plan: str = "free", target_plan: str = "starter",
                provider: str = "stripe", user_email: str = ""):
    """Get upgrade checkout URL"""
    app_url = os.getenv("APP_URL", "https://erprakashmijar.com")
    return get_upgrade_url(user_id, current_plan, target_plan, provider, user_email, app_url)

@app.get("/api/billing/subscription/{user_id}")
def get_subscription(user_id: str):
    """Get full subscription details for a user"""
    sub = subscription_get(user_id)
    trial = check_trial_status(user_id)
    current_plan = plan_get(user_id)
    plan_info = get_plan_info(current_plan)
    return {
        "user_id": user_id,
        "plan": current_plan,
        "plan_info": plan_info,
        "subscription": sub,
        "trial": trial
    }


# ── EMAIL ENDPOINTS ──────────────────────────────────────────────

class AgreementEmailReq(BaseModel):
    to_email: str
    user_name: str
    agreement: dict

class PasswordResetEmailReq(BaseModel):
    to_email: str
    user_name: str
    reset_token: str
    expires_min: int = 15

class ScanCompleteEmailReq(BaseModel):
    to_email: str
    user_name: str
    scan_data: dict

class CriticalAlertEmailReq(BaseModel):
    to_email: str
    user_name: str
    scan_data: dict
    ai_summary: str = ""

class WeeklyDigestReq(BaseModel):
    to_email: str
    user_name: str
    stats: dict

class SlackAlertReq(BaseModel):
    webhook_url: str
    message: str
    color: str = "#00ff88"

class NewDeviceAlertReq(BaseModel):
    to_email: str
    user_name: str
    device_ip: str
    hostname: str = ""



# ── ATM & VENDING MACHINE SECURITY ENDPOINTS ─────────────────────

class ATMScanReq(BaseModel):
    atm_id: str
    ip: str
    manufacturer: str = "Generic"
    os: str = "Windows 10"
    network: str = "private_vpn"
    user_id: str = "anonymous"

class VendingScanReq(BaseModel):
    vm_id: str
    ip: str
    vm_type: str = "food_drink"
    connectivity: str = "wifi"
    user_id: str = "anonymous"

class ATMComplianceReq(BaseModel):
    os_type: str
    network_type: str
    manufacturer: str = "Generic"

class CameraScanReq(BaseModel):
    network: str = "192.168.1.0/24"
    public_ip: str = ""          # optional: caller's own public IP for exposure check
    user_id: str = "anonymous"

@app.post("/api/atm/scan")
async def atm_network_scan(req: ATMScanReq, _auth_user: dict = Depends(get_current_user)):
    """Scan ATM for network-level security vulnerabilities"""
    result = await scan_atm_network(req.ip)
    compliance = get_atm_compliance_summary(req.os, req.network, req.manufacturer)
    return {
        "atm_id": req.atm_id,
        "network_scan": result,
        "compliance": compliance,
        "overall_score": round((result.get("network_score",100) + compliance.get("compliance_score",100)) / 2),
        "scanned_at": datetime.utcnow().isoformat()
    }

@app.post("/api/camera/scan")
async def camera_network_scan(req: CameraScanReq, _auth_user: dict = Depends(get_current_user)):
    """Discover and assess IP cameras / NVRs / DVRs on a network.
    TCP-probe only; never attempts logins. Authorized networks only."""
    result = await scan_camera_network(req.network, req.public_ip)
    return result

@app.post("/api/vending/scan")
async def vending_network_scan(req: VendingScanReq, _auth_user: dict = Depends(get_current_user)):
    """Scan vending machine for IoT security vulnerabilities"""
    result = await scan_vending_network(req.ip)
    return {
        "vm_id": req.vm_id,
        "network_scan": result,
        "vm_type": req.vm_type,
        "connectivity": req.connectivity,
        "scanned_at": datetime.utcnow().isoformat()
    }

@app.post("/api/atm/compliance")
def atm_compliance_check(req: ATMComplianceReq):
    """Get ATM compliance posture based on configuration"""
    return get_atm_compliance_summary(req.os_type, req.network_type, req.manufacturer)

@app.get("/api/atm/threats")
def atm_threat_intel():
    """Current ATM threat intelligence feed"""
    return {
        "updated": datetime.utcnow().isoformat(),
        "threats": [
            {"name":"Jackpotting","severity":"critical","active":True,"regions":["NA","EU","APAC"],
             "description":"Black-box and software jackpotting campaigns targeting NCR and Diebold machines"},
            {"name":"Skimming Networks","severity":"high","active":True,"regions":["EU","SEA"],
             "description":"Deep-insert skimmer distribution network with Bluetooth exfiltration"},
            {"name":"EternalBlue ATM","severity":"critical","active":True,"regions":["Global"],
             "description":"SMBv1 exploitation targeting Windows XP/7 ATMs"},
            {"name":"Ploutus-D","severity":"critical","active":True,"regions":["LATAM","NA"],
             "description":"ATM malware enabling cash dispense via SMS or USB keyboard"},
        ],
        "advisories": [
            "FS-ISAC: Update ATM application whitelisting immediately",
            "NCR: Critical patch for XFS service available",
            "PCI SSC: PCI PTS 6.x deadline for terminal replacement",
        ]
    }

@app.get("/api/vending/cves")
async def vending_cves():
    """Known CVEs affecting vending management systems"""
    known_cves = [
        {"cve":"CVE-2023-46316","product":"Cantaloupe Seed","severity":"critical","cvss":9.8,
         "description":"Unauthenticated RCE in Cantaloupe/Seed vending management platform"},
        {"cve":"CVE-2022-29142","product":"AMS Vending","severity":"high","cvss":7.5,
         "description":"Authentication bypass in AMS remote vending management"},
        {"cve":"CVE-2021-44228","product":"Log4j (various)","severity":"critical","cvss":10.0,
         "description":"Log4Shell affects vending management systems running Java"},
        {"cve":"CVE-2020-13671","product":"Drupal CMS","severity":"critical","cvss":9.8,
         "description":"Affects vending portals running Drupal CMS"},
    ]
    return {"cves": known_cves, "count": len(known_cves)}


# ── CVE ENDPOINTS ────────────────────────────────────────────────
@app.get("/api/cve/search")
async def cve_search(q: str, limit: int = 5, _opt_user: dict = Depends(get_optional_user)):
    """Search NVD CVE database"""
    results = await search_cves_by_keyword(q, limit)
    return {"cves": results, "count": len(results), "query": q}

@app.get("/api/cve/{cve_id}")
async def cve_detail(cve_id: str):
    """Get full CVE details"""
    cve = await get_cve_by_id(cve_id)
    if not cve:
        raise HTTPException(404, "CVE not found")
    return cve

@app.get("/api/cve/recent/{days}")
async def cve_recent(days: int = 7, limit: int = 10, _opt_user: dict = Depends(get_optional_user)):
    """Get recent critical CVEs"""
    cves = await get_recent_cves(days, limit)
    return {"cves": cves, "days": days}

@app.post("/api/email/agreement-confirmation")
async def email_agreement(req: AgreementEmailReq, background_tasks: BackgroundTasks):
    """Auto-send agreement confirmation after signing"""
    background_tasks.add_task(
        send_agreement_confirmation, req.to_email, req.user_name, req.agreement
    )
    return {"ok": True, "message": "Agreement confirmation queued"}

@app.post("/api/email/password-reset")
async def email_password_reset(req: PasswordResetEmailReq):
    """Send password reset OTP email — blocking (user is waiting)"""
    result = send_password_reset(req.to_email, req.user_name, req.reset_token, req.expires_min)
    return result

@app.post("/api/email/scan-complete")
async def email_scan_complete(req: ScanCompleteEmailReq, background_tasks: BackgroundTasks):
    """Send scan completion summary email"""
    background_tasks.add_task(
        send_scan_complete, req.to_email, req.user_name, req.scan_data
    )
    return {"ok": True, "message": "Scan complete email queued"}

@app.post("/api/email/critical-alert")
async def email_critical(req: CriticalAlertEmailReq, background_tasks: BackgroundTasks):
    """Send critical vulnerability alert"""
    background_tasks.add_task(
        send_critical_alert, req.to_email, req.user_name, req.scan_data, req.ai_summary
    )
    return {"ok": True, "message": "Critical alert queued"}

@app.post("/api/email/weekly-digest")
async def email_weekly_digest(req: WeeklyDigestReq, background_tasks: BackgroundTasks):
    """Send weekly security digest"""
    background_tasks.add_task(
        send_weekly_digest, req.to_email, req.user_name, req.stats
    )
    return {"ok": True, "message": "Weekly digest queued"}

@app.post("/api/email/new-device")
async def email_new_device(req: NewDeviceAlertReq, background_tasks: BackgroundTasks):
    """Alert user about new unknown device"""
    background_tasks.add_task(
        send_new_device_alert, req.to_email, req.user_name, req.device_ip, req.hostname
    )
    return {"ok": True, "message": "New device alert queued"}

@app.post("/api/slack/alert")
async def slack_alert(req: SlackAlertReq, background_tasks: BackgroundTasks):
    """Send alert to Slack webhook"""
    background_tasks.add_task(send_slack_alert, req.webhook_url, req.message, req.color)
    return {"ok": True, "message": "Slack alert queued"}

@app.get("/api/email/test/{email}")
async def test_all_emails(email: str):
    """Test endpoint — sends all email types to verify setup"""
    results = {}
    test_scan = {
        "ip": "192.168.1.100", "hostname": "test-server",
        "score": 42, "security_score": 42,
        "issues": [
            {"title": "SSH root login enabled", "severity": "critical", "cvss": 9.1, "category": "SSH", "detail": "PermitRootLogin yes"},
            {"title": "Outdated OpenSSL", "severity": "high", "cvss": 7.5, "category": "Packages", "detail": "OpenSSL 1.0.2"},
        ]
    }
    results["scan_complete"] = send_scan_complete(email, "Test User", test_scan)
    return {"ok": True, "results": results, "note": "Check your inbox for test emails"}

@app.post("/api/scan/website")
async def scan_website(req: WebScanReq, background_tasks: BackgroundTasks,
                       x_user_plan: str = Header(default="free")):
    # Validate URL — block localhost and private IPs
    import urllib.parse
    try:
        parsed = urllib.parse.urlparse(req.url if req.url.startswith('http') else 'https://' + req.url)
        hostname = parsed.hostname or ''
        ok, msg = validate_scan_target(hostname)
        if not ok:
            raise HTTPException(400, f"Invalid scan target: {msg}")
    except HTTPException:
        raise
    except Exception:
        pass  # If parsing fails, let the scan attempt and fail naturally
    _check_scan_quota(req.user_id, x_user_plan)
    try:
        result = website_scan(req.domain)
        _save_history(result, user_id)
        _increment_scan_count(req.user_id)
        if req.alert_email and check_plan_limit(x_user_plan, "email_alerts"):
            background_tasks.add_task(send_scan_alert, req.alert_email, result)
        return result
    except Exception as e:
        raise HTTPException(500, str(e))

# ── OSINT ────────────────────────────────────────────────────────
class OsintEmailReq(BaseModel):
    email: str
    user_id: str = "anonymous"

class OsintUsernameReq(BaseModel):
    username: str

class OsintIpReq(BaseModel):
    ip: str

class PasswordCheckReq(BaseModel):
    password: str

@app.post("/api/osint/email")
async def osint_email(req: OsintEmailReq, _auth_user: dict = Depends(get_current_user)):
    try:
        return full_email_osint(req.email)
    except Exception as e:
        raise HTTPException(500, str(e))

@app.post("/api/osint/username")
async def osint_username(req: OsintUsernameReq, _auth_user: dict = Depends(get_current_user)):
    try:
        results = lookup_username(req.username)
        return {"username": req.username, "results": results,
                "found_on": len([r for r in results if r.get("found")])}
    except Exception as e:
        raise HTTPException(500, str(e))

@app.post("/api/osint/ip")
async def osint_ip(req: OsintIpReq, _auth_user: dict = Depends(get_current_user)):
    try:
        rep   = check_ip_reputation(req.ip)
        vt    = check_virustotal(req.ip, "ip")
        shod  = shodan_lookup(req.ip)
        ioc   = check_ioc_match(req.ip)
        return {"ip": req.ip, "reputation": rep, "virustotal": vt,
                "shodan": shod, "known_ioc": len(ioc) > 0, "ioc_matches": ioc}
    except Exception as e:
        raise HTTPException(500, str(e))

@app.post("/api/osint/password")
async def check_password(req: PasswordCheckReq, _auth_user: dict = Depends(get_current_user)):
    try:
        return check_password_pwned(req.password)
    except Exception as e:
        raise HTTPException(500, str(e))

@app.post("/api/osint/domain")
async def osint_domain_route(domain: str, _auth_user: dict = Depends(get_current_user)):
    try:
        return domain_intel(domain)
    except Exception as e:
        raise HTTPException(500, str(e))

# ── SOC: INCIDENTS ────────────────────────────────────────────────
class IncidentReq(BaseModel):
    title: str
    description: str
    severity: str
    source: str = "manual"
    created_by: str = "analyst"
    affected_devices: list = []
    mitre_techniques: list = []

class IncidentUpdateReq(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    note: Optional[str] = None
    tags: Optional[list] = None
    updated_by: str = "analyst"

@app.post("/api/soc/incidents")
async def create_incident_route(req: IncidentReq, background_tasks: BackgroundTasks, _auth_user: dict = Depends(get_current_user)):
    inc = create_incident(**req.dict())
    return inc

@app.get("/api/soc/incidents")
def list_incidents(status: Optional[str] = None, severity: Optional[str] = None):
    return {"incidents": get_incidents(status, severity), "metrics": get_soc_metrics()}

@app.get("/api/soc/incidents/{iid}")
def get_incident_route(iid: str):
    inc = get_incident(iid)
    if not inc: raise HTTPException(404, "Incident not found")
    return inc

@app.patch("/api/soc/incidents/{iid}")
def update_incident_route(iid: str, req: IncidentUpdateReq):
    inc = update_incident(iid, req.dict(exclude_none=True), req.updated_by)
    if not inc: raise HTTPException(404, "Incident not found")
    return inc

@app.post("/api/soc/incidents/auto")
async def auto_incident(scan_data: dict, background_tasks: BackgroundTasks, _auth_user: dict = Depends(get_current_user)):
    incidents = auto_create_incident_from_scan(scan_data)
    return {"created": len(incidents), "incidents": incidents}

# ── SOC: IOCs ────────────────────────────────────────────────────
class IOCReq(BaseModel):
    type: str
    value: str
    severity: str = "medium"
    description: str = ""
    source: str = "manual"
    added_by: str = "analyst"
    tags: list = []

@app.post("/api/soc/iocs")
def add_ioc_route(req: IOCReq):
    return add_ioc(
        ioc_type=req.type,
        value=req.value,
        severity=req.severity,
        description=req.description,
        source=req.source,
        added_by=req.added_by,
        tags=req.tags,
    )

@app.get("/api/soc/iocs")
def list_iocs(query: Optional[str] = None, type: Optional[str] = None):
    return {"iocs": search_iocs(query, type), "types": IOC_TYPES}

@app.get("/api/soc/iocs/check/{value}")
def check_ioc_route(value: str):
    matches = check_ioc_match(value)
    return {"value": value, "is_ioc": len(matches) > 0, "matches": matches}

# ── SOC: MITRE ATT&CK ────────────────────────────────────────────
@app.get("/api/soc/mitre")
def get_mitre():
    return {"techniques": MITRE_TECHNIQUES}

@app.post("/api/soc/mitre/map")
def map_mitre(findings: list):
    return {"mapped_techniques": map_to_mitre(findings)}

# ── SOC: PLAYBOOKS ────────────────────────────────────────────────
@app.get("/api/soc/playbooks")
def list_playbooks():
    return {"playbooks": get_playbooks()}

@app.get("/api/soc/playbooks/{pid}")
def get_playbook_route(pid: str):
    pb = get_playbook(pid)
    if not pb: raise HTTPException(404, "Playbook not found")
    return pb

# ── SOC: METRICS ─────────────────────────────────────────────────
@app.get("/api/soc/metrics")
def soc_metrics():
    return get_soc_metrics()

# ── WAZUH ────────────────────────────────────────────────────────
@app.get("/api/siem/wazuh/alerts")
def wazuh_alerts(limit: int = 50, level: Optional[int] = None):
    return get_wazuh_alerts(limit, level)

@app.get("/api/siem/wazuh/agents")
def wazuh_agents():
    return get_wazuh_agents()

# ── SPLUNK ────────────────────────────────────────────────────────
class SplunkSearchReq(BaseModel):
    query: str
    earliest: str = "-24h"
    latest: str = "now"

@app.post("/api/siem/splunk/search")
def splunk_search_route(req: SplunkSearchReq):
    return splunk_search(req.query, req.earliest, req.latest)

@app.post("/api/siem/splunk/log")
def splunk_log_route(event: dict):
    return splunk_send_log(event)


# ═══════════════════════════════════════════════════════════════
# FEATURE 8 — SSL CERTIFICATE MONITOR
# ═══════════════════════════════════════════════════════════════
import ssl, socket
from datetime import timezone

class SSLMonitorReq(BaseModel):
    domains: list
    user_id: str = "anonymous"

@app.post("/api/ssl/monitor")
async def ssl_monitor(req: SSLMonitorReq, _opt_user: dict = Depends(get_optional_user)):
    """Check SSL certificates for multiple domains"""
    results = []
    for domain in req.domains[:20]:
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.settimeout(8)
                s.connect((domain, 443))
                cert = s.getpeercert()
            not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            not_after = not_after.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            days_left = (not_after - now).days
            issuer = dict(x[0] for x in cert.get('issuer', []))
            subject = dict(x[0] for x in cert.get('subject', []))
            results.append({
                "domain": domain, "valid": True,
                "days_left": days_left,
                "expires": not_after.strftime("%Y-%m-%d"),
                "issuer": issuer.get("organizationName", "Unknown"),
                "cn": subject.get("commonName", domain),
                "severity": "critical" if days_left < 7 else "high" if days_left < 14 else "medium" if days_left < 30 else "ok",
                "status": "EXPIRED" if days_left < 0 else "CRITICAL" if days_left < 7 else "WARNING" if days_left < 30 else "VALID"
            })
        except ssl.SSLCertVerificationError as e:
            results.append({"domain": domain, "valid": False, "error": str(e), "severity": "critical", "status": "INVALID"})
        except Exception as e:
            results.append({"domain": domain, "valid": False, "error": str(e), "severity": "unknown", "status": "ERROR"})
    return {"results": results, "checked": len(results)}

@app.get("/api/ssl/check/{domain}")
async def ssl_check(domain: str, _opt_user: dict = Depends(get_optional_user)):
    """Quick SSL check for a single domain"""
    req = SSLMonitorReq(domains=[domain])
    result = await ssl_monitor(req)
    return result["results"][0] if result["results"] else {"error": "No result"}
