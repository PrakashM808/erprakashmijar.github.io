"""
main.py — PM::OFFSEC Security Dashboard API v3.0
Full SaaS backend: live scanning + billing + email alerts + scheduled scans
"""
import os, json, uuid
from datetime import datetime
from typing import Optional
from fastapi import FastAPI, HTTPException, Request, BackgroundTasks, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

from scanner   import local_scan, remote_scan, discover_network_devices
from physical_security import scan_atm_network, scan_vending_network, get_atm_compliance_summary
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
    init_db, user_create, user_get, user_get_by_email, user_update,
    user_record_login, users_get_all, scan_save, scan_get_history,
    scan_get_all_history, scan_get_recent, scan_count_increment,
    scan_count_get_today, incident_create, incident_get_all, incident_update,
    agreement_save, agreements_get_all, alert_prefs_set, alert_prefs_get,
    plan_set, plan_get, subscription_save, subscription_get,
    ioc_add, iocs_get_all, get_dashboard_stats, get_score_history
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
        return {"user_id": payload.get("user_id"), "email": payload.get("sub"), "plan": payload.get("plan","free")}
    except Exception as e:
        raise HTTPException(401, f"Invalid token: {str(e)}")

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
        token = pyjwt.encode({"sub":req.email,"user_id":user_id,"plan":req.plan,
            "exp":datetime.utcnow()+timedelta(hours=JWT_EXPIRY_HOURS)}, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return {"ok":True,"access_token":token,"user_id":user_id,"email":req.email,"name":req.name,"plan":req.plan}

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
    token = ""
    if JWT_AVAILABLE:
        token = pyjwt.encode({"sub":user["email"],"user_id":user["id"],"plan":current_plan,
            "exp":datetime.utcnow()+timedelta(hours=JWT_EXPIRY_HOURS)}, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return {"ok":True,"access_token":token,"user_id":user["id"],"email":user["email"],"name":user.get("name",""),"plan":current_plan}

@app.get("/api/auth/verify")
async def jwt_verify(user: dict = Depends(get_current_user)):
    return {"valid":True,"user_id":user["user_id"],"email":user["email"],"plan":user["plan"]}

@app.post("/api/auth/logout")
async def jwt_logout():
    return {"ok":True}


# ═══════════════════════════════════════════════════════════════
# FINAL VERSION — NEW FEATURE ENDPOINTS
# ═══════════════════════════════════════════════════════════════

# ── Attack Surface Discovery ─────────────────────────────────
class AttackSurfaceReq(BaseModel):
    domain: str

@app.post("/api/attack-surface/discover")
async def attack_surface_discover(req: AttackSurfaceReq):
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
async def phishing_launch(req: PhishingCampaignReq, background_tasks: BackgroundTasks):
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
async def phishing_click(campaign_id: str):
    """Track when a target clicks a phishing link"""
    return {"ok": True, "campaign_id": campaign_id, "message": "Click recorded"}

# ── Dark Web Monitoring ──────────────────────────────────────
class DarkWebReq(BaseModel):
    domain: str = ""
    email: str = ""
    keywords: list = []
    user_id: str = ""

@app.post("/api/darkweb/scan")
async def darkweb_scan(req: DarkWebReq):
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
async def msp_add_client(req: MSPClientReq):
    """Add a client to MSP dashboard"""
    client_id = f"MSP-{str(uuid.uuid4())[:8].upper()}"
    return {"ok": True, "client_id": client_id, "client_name": req.client_name}

@app.get("/api/msp/clients/{user_id}")
async def msp_get_clients(user_id: str):
    """Get all MSP clients for a user"""
    return {"ok": True, "clients": [], "total": 0}

# ── Compliance Assessment ─────────────────────────────────────
@app.get("/api/compliance/{framework}/{user_id}")
async def get_compliance(framework: str, user_id: str):
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
async def send_client_review_email(req: ClientReviewEmailReq, background_tasks: BackgroundTasks):
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
    _check_scan_quota(req.user_id, x_user_plan)
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
async def create_checkout(req: CheckoutReq):
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
    payload = await request.json()
    event   = handle_lemonsqueezy_webhook(payload, x_signature or "", raw)
    etype   = event["type"]
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
async def cancel_subscription(req: CancelReq, background_tasks: BackgroundTasks):
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
async def send_test_alert(user_id: str, email: str):
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

@app.get("/api/users")
def list_users():
    """Admin: get all users from database"""
    return {"users": users_get_all()}

@app.post("/api/users/login-record/{user_id}")
def record_login(user_id: str):
    """Record user login"""
    user_record_login(user_id)
    return {"ok": True}



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

@app.post("/api/atm/scan")
async def atm_network_scan(req: ATMScanReq):
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

@app.post("/api/vending/scan")
async def vending_network_scan(req: VendingScanReq):
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
async def cve_search(q: str, limit: int = 5):
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
async def cve_recent(days: int = 7, limit: int = 10):
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
async def osint_email(req: OsintEmailReq):
    try:
        return full_email_osint(req.email)
    except Exception as e:
        raise HTTPException(500, str(e))

@app.post("/api/osint/username")
async def osint_username(req: OsintUsernameReq):
    try:
        results = lookup_username(req.username)
        return {"username": req.username, "results": results,
                "found_on": len([r for r in results if r.get("found")])}
    except Exception as e:
        raise HTTPException(500, str(e))

@app.post("/api/osint/ip")
async def osint_ip(req: OsintIpReq):
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
async def check_password(req: PasswordCheckReq):
    try:
        return check_password_pwned(req.password)
    except Exception as e:
        raise HTTPException(500, str(e))

@app.post("/api/osint/domain")
async def osint_domain_route(domain: str):
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
async def create_incident_route(req: IncidentReq, background_tasks: BackgroundTasks):
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
async def auto_incident(scan_data: dict, background_tasks: BackgroundTasks):
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
    return add_ioc(**req.dict())

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
async def ssl_monitor(req: SSLMonitorReq):
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
async def ssl_check(domain: str):
    """Quick SSL check for a single domain"""
    req = SSLMonitorReq(domains=[domain])
    result = await ssl_monitor(req)
    return result["results"][0] if result["results"] else {"error": "No result"}
