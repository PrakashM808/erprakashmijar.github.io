"""
main.py — PM::OFFSEC Security Dashboard API v3.0
Full SaaS backend: live scanning + billing + email alerts + scheduled scans
"""
import os, json, uuid
from datetime import datetime
from typing import Optional
from fastapi import FastAPI, HTTPException, Request, BackgroundTasks, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

from scanner   import local_scan, remote_scan, discover_network_devices
from billing   import (PLANS, init_stripe, create_stripe_checkout,
                       create_lemonsqueezy_checkout, handle_stripe_webhook,
                       handle_lemonsqueezy_webhook, check_plan_limit, get_plan_info)
from alerts    import (send_scan_alert, send_weekly_report,
                       send_welcome_email, send_subscription_email, send_email)
from scheduler import (add_schedule, remove_schedule, pause_schedule,
                       resume_schedule, get_all_schedules, get_schedule,
                       CRON_PRESETS, start_scheduler, stop_scheduler)
import anthropic

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

# ── In-memory stores (upgrade to PostgreSQL for production) ──────
scan_history: dict  = {}   # ip -> list of {date, score, timestamp}
user_plans:   dict  = {}   # user_id -> plan_key
user_subs:    dict  = {}   # user_id -> subscription info
scan_counts:  dict  = {}   # user_id:YYYY-MM-DD -> count
alert_prefs:  dict  = {}   # user_id -> {email, enabled}

# ── LIFECYCLE ────────────────────────────────────────────────────
@app.on_event("startup")
async def startup():
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
        _save_history(result)
        _increment_scan_count(user_id)
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
        _save_history(result)
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
def _save_history(result: dict):
    ip = result.get("ip", "127.0.0.1")
    if ip not in scan_history:
        scan_history[ip] = []
    scan_history[ip].append({
        "date": datetime.now().strftime("%b %d"),
        "score": result["security_score"],
        "timestamp": result["timestamp"]
    })
    if len(scan_history[ip]) > 20:
        scan_history[ip] = scan_history[ip][-20:]
    result["score_history"] = scan_history[ip][-5:]

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

@app.post("/api/scan/website")
async def scan_website(req: WebScanReq, background_tasks: BackgroundTasks,
                       x_user_plan: str = Header(default="free")):
    _check_scan_quota(req.user_id, x_user_plan)
    try:
        result = website_scan(req.domain)
        _save_history(result)
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

