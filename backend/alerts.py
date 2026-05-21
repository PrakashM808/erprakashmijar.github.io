"""
alerts.py — SendGrid email alert system
Sends security alerts when scans find critical/high issues
"""
import os
import json
from datetime import datetime
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, To, From, Subject, HtmlContent

SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY", "")
FROM_EMAIL       = os.getenv("ALERT_FROM_EMAIL", "alerts@erprakashmijar.com")
FROM_NAME        = os.getenv("ALERT_FROM_NAME",  "PM::OFFSEC Security Dashboard")

# ── HTML EMAIL TEMPLATES ─────────────────────────────────────────

def _base_template(title: str, content: str, cta_url: str = "", cta_text: str = "") -> str:
    cta_block = f"""
    <div style="text-align:center;margin-top:2rem">
      <a href="{cta_url}" style="display:inline-block;background:#00ff88;color:#020d06;font-family:'Courier New',monospace;font-size:14px;font-weight:700;letter-spacing:2px;padding:12px 28px;text-decoration:none;border-radius:4px">{cta_text}</a>
    </div>""" if cta_url else ""
    return f"""
<!DOCTYPE html><html><head><meta charset="UTF-8"/></head>
<body style="margin:0;padding:0;background:#03070f;font-family:'Courier New',monospace">
  <div style="max-width:600px;margin:0 auto;padding:40px 20px">
    <!-- Header -->
    <div style="background:#060d1a;border:1px solid rgba(0,255,136,.15);border-radius:8px;overflow:hidden;margin-bottom:20px">
      <div style="height:3px;background:linear-gradient(90deg,#00ff88,#00d4ff,#7b2fff)"></div>
      <div style="padding:24px 28px;border-bottom:1px solid rgba(0,255,136,.08)">
        <div style="font-size:22px;color:#e8f4f8;letter-spacing:4px">SEC<span style="color:#00ff88">AUDIT</span></div>
        <div style="font-size:11px;color:#2a4a62;letter-spacing:3px;margin-top:4px">PM::OFFSEC SECURITY DASHBOARD</div>
      </div>
      <div style="padding:28px">
        <h1 style="color:#e8f4f8;font-size:20px;margin:0 0 16px;letter-spacing:2px">{title}</h1>
        {content}
        {cta_block}
      </div>
    </div>
    <!-- Footer -->
    <div style="text-align:center;padding:16px">
      <p style="color:#2a4a62;font-size:11px;letter-spacing:1px;margin:0">PM::OFFSEC SECURITY DASHBOARD · erprakashmijar.com</p>
      <p style="color:#2a4a62;font-size:10px;margin:6px 0 0">You're receiving this because you enabled email alerts. <a href="{os.getenv('APP_URL','https://erprakashmijar.com')}/dashboard/index.html" style="color:#00d4ff">Manage alerts</a></p>
    </div>
  </div>
</body></html>"""

def _severity_color(sev: str) -> str:
    return {"critical": "#ff3b5c", "high": "#ff8c42", "medium": "#f5c842", "low": "#4dd9ac"}.get(sev, "#7aafc8")

def _severity_bg(sev: str) -> str:
    return {"critical": "rgba(255,59,92,.12)", "high": "rgba(255,140,66,.1)", "medium": "rgba(245,200,66,.08)", "low": "rgba(77,217,172,.07)"}.get(sev, "rgba(255,255,255,.04)")

def _issue_row(issue: dict) -> str:
    col = _severity_color(issue.get("severity", "medium"))
    bg  = _severity_bg(issue.get("severity", "medium"))
    return f"""
    <div style="background:{bg};border-left:3px solid {col};border-radius:4px;padding:12px 14px;margin-bottom:8px">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <span style="color:{col};font-size:10px;letter-spacing:2px;font-weight:700">{issue.get('severity','').upper()}</span>
        <span style="color:#2a4a62;font-size:10px">CVSS {issue.get('cvss','—')}</span>
      </div>
      <div style="color:#c0dce8;font-size:13px;margin-top:6px">{issue.get('title','')}</div>
      <div style="color:#2a4a62;font-size:11px;margin-top:3px">{issue.get('category','')} · {issue.get('detail','')}</div>
    </div>"""

# ── EMAIL SENDERS ────────────────────────────────────────────────

def send_email(to_email: str, subject: str, html: str) -> dict:
    """Core send function using SendGrid"""
    if not SENDGRID_API_KEY:
        return {"ok": False, "error": "SENDGRID_API_KEY not configured in .env"}
    try:
        message = Mail(
            from_email=(FROM_EMAIL, FROM_NAME),
            to_emails=to_email,
            subject=subject,
            html_content=html
        )
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        response = sg.send(message)
        return {"ok": True, "status_code": response.status_code}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def send_scan_alert(to_email: str, scan_data: dict) -> dict:
    """Send alert email after a scan finds critical/high issues"""
    hostname  = scan_data.get("hostname", "Unknown")
    ip        = scan_data.get("ip", "—")
    score     = scan_data.get("security_score", 0)
    issues    = scan_data.get("issues", [])
    timestamp = datetime.now().strftime("%B %d, %Y at %H:%M UTC")

    critical = [i for i in issues if i.get("severity") == "critical"]
    high     = [i for i in issues if i.get("severity") == "high"]
    urgent   = critical + high

    if not urgent:
        return {"ok": True, "skipped": "No critical/high issues to alert"}

    score_color = "#00ff88" if score >= 80 else "#f5c842" if score >= 60 else "#ff3b5c"
    subject = f"🚨 {len(critical)} Critical Issue{'s' if len(critical)!=1 else ''} Found — {hostname}" if critical else f"⚠️ Security Alert — {hostname} ({len(high)} High Issues)"

    issues_html = "".join(_issue_row(i) for i in urgent[:8])
    more = f'<p style="color:#2a4a62;font-size:11px;text-align:center;margin-top:8px">+ {len(urgent)-8} more issues — view full report in dashboard</p>' if len(urgent) > 8 else ""

    content = f"""
    <div style="background:rgba(0,255,136,.04);border:1px solid rgba(0,255,136,.1);border-radius:6px;padding:16px 18px;margin-bottom:20px">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <div>
          <div style="color:#e8f4f8;font-size:15px;font-weight:700">{hostname}</div>
          <div style="color:#2a4a62;font-size:12px;margin-top:3px">{ip} · {scan_data.get('os','Linux')}</div>
          <div style="color:#2a4a62;font-size:11px;margin-top:2px">Scanned: {timestamp}</div>
        </div>
        <div style="text-align:right">
          <div style="font-size:36px;color:{score_color};font-weight:700;line-height:1">{score}</div>
          <div style="color:#2a4a62;font-size:10px;letter-spacing:2px">SECURITY SCORE</div>
        </div>
      </div>
    </div>
    <div style="margin-bottom:12px">
      <div style="display:flex;gap:12px;margin-bottom:16px">
        <div style="background:rgba(255,59,92,.1);border:1px solid rgba(255,59,92,.25);border-radius:5px;padding:10px 16px;text-align:center;flex:1">
          <div style="color:#ff3b5c;font-size:24px;font-weight:700">{len(critical)}</div>
          <div style="color:#2a4a62;font-size:10px;letter-spacing:2px">CRITICAL</div>
        </div>
        <div style="background:rgba(255,140,66,.1);border:1px solid rgba(255,140,66,.22);border-radius:5px;padding:10px 16px;text-align:center;flex:1">
          <div style="color:#ff8c42;font-size:24px;font-weight:700">{len(high)}</div>
          <div style="color:#2a4a62;font-size:10px;letter-spacing:2px">HIGH</div>
        </div>
        <div style="background:rgba(0,255,136,.06);border:1px solid rgba(0,255,136,.15);border-radius:5px;padding:10px 16px;text-align:center;flex:1">
          <div style="color:#00ff88;font-size:24px;font-weight:700">{len(issues)}</div>
          <div style="color:#2a4a62;font-size:10px;letter-spacing:2px">TOTAL</div>
        </div>
      </div>
      <div style="color:#00d4ff;font-size:11px;letter-spacing:2px;margin-bottom:10px">// TOP FINDINGS</div>
      {issues_html}{more}
    </div>"""

    html = _base_template(
        title="SECURITY SCAN ALERT",
        content=content,
        cta_url=os.getenv("APP_URL", "https://erprakashmijar.com") + "/dashboard/index.html",
        cta_text="VIEW FULL REPORT →"
    )
    return send_email(to_email, subject, html)

def send_weekly_report(to_email: str, user_name: str, devices: list) -> dict:
    """Send a weekly summary email across all devices"""
    all_issues = [i for d in devices for i in d.get("issues", [])]
    total_critical = len([i for i in all_issues if i.get("severity") == "critical"])
    avg_score = round(sum(d.get("security_score", 0) for d in devices) / len(devices)) if devices else 0

    devices_html = "".join(f"""
    <div style="background:rgba(255,255,255,.02);border:1px solid rgba(0,255,136,.06);border-radius:5px;padding:12px 14px;margin-bottom:8px;display:flex;justify-content:space-between;align-items:center">
      <div>
        <div style="color:#c0dce8;font-size:13px">{d.get('hostname','—')}</div>
        <div style="color:#2a4a62;font-size:11px">{d.get('ip','—')} · {d.get('os','Linux')}</div>
      </div>
      <div style="text-align:right">
        <div style="font-size:22px;color:{'#00ff88' if d.get('security_score',0)>=80 else '#f5c842' if d.get('security_score',0)>=60 else '#ff3b5c'};font-weight:700">{d.get('security_score','—')}</div>
        <div style="color:#2a4a62;font-size:10px">{len([i for i in d.get('issues',[]) if i.get('severity')=='critical'])}C · {len([i for i in d.get('issues',[]) if i.get('severity')=='high'])}H</div>
      </div>
    </div>""" for d in devices)

    content = f"""
    <p style="color:#7aafc8;font-size:13px;margin:0 0 20px">Hello {user_name.split()[0]}, here's your weekly security summary across {len(devices)} device{'s' if len(devices)!=1 else ''}.</p>
    <div style="display:flex;gap:12px;margin-bottom:20px">
      <div style="background:rgba(0,255,136,.06);border:1px solid rgba(0,255,136,.15);border-radius:5px;padding:12px;text-align:center;flex:1">
        <div style="color:#00ff88;font-size:28px;font-weight:700">{avg_score}</div>
        <div style="color:#2a4a62;font-size:10px;letter-spacing:2px">AVG SCORE</div>
      </div>
      <div style="background:rgba(255,59,92,.08);border:1px solid rgba(255,59,92,.2);border-radius:5px;padding:12px;text-align:center;flex:1">
        <div style="color:#ff3b5c;font-size:28px;font-weight:700">{total_critical}</div>
        <div style="color:#2a4a62;font-size:10px;letter-spacing:2px">CRITICAL ISSUES</div>
      </div>
      <div style="background:rgba(0,212,255,.06);border:1px solid rgba(0,212,255,.12);border-radius:5px;padding:12px;text-align:center;flex:1">
        <div style="color:#00d4ff;font-size:28px;font-weight:700">{len(devices)}</div>
        <div style="color:#2a4a62;font-size:10px;letter-spacing:2px">DEVICES</div>
      </div>
    </div>
    <div style="color:#00d4ff;font-size:11px;letter-spacing:2px;margin-bottom:10px">// DEVICE STATUS</div>
    {devices_html}"""

    html = _base_template(
        title="WEEKLY SECURITY REPORT",
        content=content,
        cta_url=os.getenv("APP_URL", "https://erprakashmijar.com") + "/dashboard/index.html",
        cta_text="OPEN DASHBOARD →"
    )
    return send_email(to_email, f"Weekly Security Report — {len(devices)} Devices · Avg Score {avg_score}", html)

def send_welcome_email(to_email: str, user_name: str, plan: str) -> dict:
    """Send welcome email after registration"""
    plan_info = {"free": "Free", "starter": "Starter ($19/mo)", "professional": "Professional ($79/mo)", "enterprise": "Enterprise ($199/mo)"}.get(plan, "Free")
    content = f"""
    <p style="color:#7aafc8;font-size:14px;line-height:1.8;margin:0 0 20px">Welcome to PM::OFFSEC Security Dashboard, {user_name.split()[0]}!<br>Your account is active on the <strong style="color:#00ff88">{plan_info}</strong> plan.</p>
    <div style="background:rgba(0,255,136,.04);border:1px solid rgba(0,255,136,.1);border-radius:6px;padding:16px 18px;margin-bottom:20px">
      <div style="color:#00d4ff;font-size:11px;letter-spacing:2px;margin-bottom:12px">// GETTING STARTED</div>
      <div style="color:#c0dce8;font-size:12px;line-height:2">
        1. Open your dashboard → click <strong style="color:#00ff88">SCAN DEVICE</strong><br>
        2. Choose Local (this machine) or Remote (via SSH)<br>
        3. Get your security score in seconds<br>
        4. Use AI Analysis to get exact remediation commands<br>
        5. Download your report and fix the issues
      </div>
    </div>"""
    html = _base_template(
        title="WELCOME TO PM::OFFSEC",
        content=content,
        cta_url=os.getenv("APP_URL", "https://erprakashmijar.com") + "/dashboard/index.html",
        cta_text="OPEN DASHBOARD →"
    )
    return send_email(to_email, "Welcome to PM::OFFSEC Security Dashboard", html)

def send_subscription_email(to_email: str, user_name: str, plan: str, action: str = "upgraded") -> dict:
    """Send email when subscription changes"""
    plan_info = PLANS.get(plan, PLANS["free"])
    content = f"""
    <p style="color:#7aafc8;font-size:14px;line-height:1.8;margin:0 0 20px">Hi {user_name.split()[0]}, your subscription has been <strong style="color:#00ff88">{action}</strong>.</p>
    <div style="background:rgba(0,255,136,.04);border:1px solid rgba(0,255,136,.1);border-radius:6px;padding:16px 18px;margin-bottom:20px">
      <div style="color:#e8f4f8;font-size:16px;font-weight:700;margin-bottom:8px">{plan_info['name']} Plan</div>
      <div style="color:#2a4a62;font-size:13px;margin-bottom:12px">${plan_info['price']}/month</div>
      {''.join(f'<div style="color:#c0dce8;font-size:12px;padding:4px 0;border-bottom:1px solid rgba(0,255,136,.04)">✓ {f}</div>' for f in plan_info['features'])}
    </div>"""
    html = _base_template(
        title=f"SUBSCRIPTION {action.upper()}",
        content=content,
        cta_url=os.getenv("APP_URL", "https://erprakashmijar.com") + "/dashboard/index.html",
        cta_text="OPEN DASHBOARD →"
    )
    return send_email(to_email, f"Your PM::OFFSEC Subscription — {plan_info['name']} Plan", html)

# ═══════════════════════════════════════════════════════════════
# NEW EMAIL FUNCTIONS — PM::OFFSEC v2.0
# ═══════════════════════════════════════════════════════════════

def send_agreement_confirmation(to_email: str, user_name: str, agreement: dict) -> dict:
    """Auto-send agreement confirmation immediately after signing"""
    agr_id   = agreement.get("id", "")
    org      = agreement.get("org", "")
    eng_type = agreement.get("type", "")
    start    = agreement.get("start", "")
    end      = agreement.get("end", "")
    signed   = agreement.get("timestamp", datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"))

    content = f"""
    <p style="color:#7aafc8;font-size:13px;line-height:1.7;margin:0 0 20px">
      Your Security Engagement Agreement has been signed and recorded. Please keep this for your records.
    </p>

    <!-- Agreement details card -->
    <div style="background:rgba(0,255,136,.04);border:1px solid rgba(0,255,136,.12);border-radius:6px;padding:20px;margin-bottom:20px">
      <div style="font-size:10px;color:#00ff88;letter-spacing:3px;margin-bottom:14px">AGREEMENT DETAILS</div>
      {''.join(f'<div style="display:flex;justify-content:space-between;padding:7px 0;border-bottom:1px solid rgba(0,255,136,.06)"><span style="color:#2a4a62;font-size:11px">{k}</span><span style="color:#c0dce8;font-size:12px">{v}</span></div>' for k,v in [
        ("Agreement ID", agr_id),
        ("Organization", org),
        ("Engagement Type", eng_type),
        ("Authorized Start", start),
        ("Authorized End", end),
        ("Signed", signed),
      ] if v)}
    </div>

    <!-- Legal notice -->
    <div style="background:rgba(255,59,92,.06);border:1px solid rgba(255,59,92,.15);border-radius:6px;padding:16px;margin-bottom:20px">
      <div style="font-size:10px;color:#ff3b5c;letter-spacing:2px;margin-bottom:8px">⚖ LEGAL REMINDER</div>
      <p style="color:#7aafc8;font-size:12px;line-height:1.7;margin:0">
        By signing this agreement you confirmed authorization to test only the systems listed in scope.
        Unauthorized testing is a federal crime under <strong style="color:#c0dce8">CFAA 18 U.S.C. § 1030</strong>.
        This agreement is legally binding under the ESIGN Act (15 U.S.C. § 7001).
      </p>
    </div>

    <p style="color:#2a4a62;font-size:12px;margin:0">
      To view or download your full agreement, log in to your dashboard.
    </p>
    """

    html = _base_template(
        f"Agreement Signed — {agr_id}",
        content,
        f"{os.getenv('APP_URL','https://erprakashmijar.com')}/dashboard/index.html",
        "VIEW DASHBOARD →"
    )
    return send_email(to_email, f"PM::OFFSEC — Security Engagement Agreement {agr_id}", html)


def send_password_reset(to_email: str, user_name: str, reset_token: str, expires_min: int = 15) -> dict:
    """Send password reset OTP email"""
    reset_url = f"{os.getenv('APP_URL','https://erprakashmijar.com')}/forgot-password.html?token={reset_token}"

    content = f"""
    <p style="color:#7aafc8;font-size:13px;line-height:1.7;margin:0 0 20px">
      We received a request to reset your password. Use the code below or click the button.
      This code expires in <strong style="color:#c0dce8">{expires_min} minutes</strong>.
    </p>

    <!-- OTP display -->
    <div style="text-align:center;margin:24px 0">
      <div style="display:inline-block;background:rgba(0,255,136,.06);border:2px solid rgba(0,255,136,.25);border-radius:8px;padding:20px 40px">
        <div style="font-size:10px;color:#2a4a62;letter-spacing:3px;margin-bottom:10px">RESET CODE</div>
        <div style="font-size:36px;color:#00ff88;letter-spacing:10px;font-weight:700">{reset_token}</div>
        <div style="font-size:10px;color:#2a4a62;margin-top:8px">Expires in {expires_min} minutes</div>
      </div>
    </div>

    <div style="background:rgba(245,158,11,.06);border:1px solid rgba(245,158,11,.2);border-radius:6px;padding:14px;margin-top:20px">
      <div style="font-size:11px;color:#f59e0b;letter-spacing:1px">⚠ SECURITY NOTICE</div>
      <p style="color:#7aafc8;font-size:12px;margin:8px 0 0;line-height:1.6">
        If you didn't request this reset, ignore this email. Your password will not change.
        Never share this code with anyone — PM::OFFSEC staff will never ask for it.
      </p>
    </div>
    """

    html = _base_template(
        "Password Reset Request",
        content,
        reset_url,
        "RESET PASSWORD →"
    )
    return send_email(to_email, "PM::OFFSEC — Password Reset Code", html)


def send_critical_alert(to_email: str, user_name: str, scan_data: dict, ai_summary: str = "") -> dict:
    """Urgent email for critical/high severity findings with AI summary"""
    issues    = scan_data.get("issues", [])
    critical  = [i for i in issues if i.get("severity") == "critical"]
    high      = [i for i in issues if i.get("severity") == "high"]
    hostname  = scan_data.get("hostname", scan_data.get("ip", "Unknown"))
    score     = scan_data.get("score", scan_data.get("security_score", 0))
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    score_color = "#ff3b5c" if score < 50 else "#f59e0b" if score < 70 else "#00ff88"

    top_issues = (critical + high)[:5]
    issue_rows = "".join(_issue_row(i) for i in top_issues)

    ai_block = f"""
    <div style="background:rgba(123,47,255,.06);border:1px solid rgba(123,47,255,.2);border-radius:6px;padding:16px;margin:16px 0">
      <div style="font-size:10px;color:#c084fc;letter-spacing:2px;margin-bottom:10px">🤖 AI ANALYSIS SUMMARY</div>
      <p style="color:#c0dce8;font-size:12px;line-height:1.7;margin:0">{ai_summary}</p>
    </div>""" if ai_summary else ""

    content = f"""
    <div style="background:rgba(255,59,92,.08);border:1px solid rgba(255,59,92,.2);border-radius:6px;padding:14px 18px;margin-bottom:20px">
      <div style="font-size:10px;color:#ff3b5c;letter-spacing:2px">🚨 CRITICAL SECURITY ALERT</div>
      <p style="color:#c0dce8;font-size:13px;margin:8px 0 0">
        <strong style="color:#ff3b5c">{len(critical)} critical</strong> and
        <strong style="color:#ff8c42">{len(high)} high</strong> severity issues found on
        <strong style="color:#e8f4f8">{hostname}</strong> at {timestamp}.
      </p>
    </div>

    <!-- Score -->
    <div style="display:flex;align-items:center;gap:20px;margin-bottom:20px">
      <div style="background:rgba(0,0,0,.3);border:1px solid rgba(255,255,255,.07);border-radius:8px;padding:16px 24px;text-align:center;min-width:100px">
        <div style="font-size:32px;color:{score_color};font-weight:700">{score}</div>
        <div style="font-size:10px;color:#2a4a62;letter-spacing:2px;margin-top:4px">SECURITY SCORE</div>
      </div>
      <div>
        <div style="color:#c0dce8;font-size:13px;margin-bottom:6px">
          Device: <strong>{hostname}</strong>
        </div>
        <div style="color:#7aafc8;font-size:12px">
          {len(critical)} Critical · {len(high)} High · {len([i for i in issues if i.get('severity')=='medium'])} Medium
        </div>
      </div>
    </div>

    {ai_block}

    <div style="font-size:10px;color:#2a4a62;letter-spacing:2px;margin-bottom:10px">TOP ISSUES REQUIRING IMMEDIATE ATTENTION</div>
    {issue_rows}

    <p style="color:#7aafc8;font-size:12px;margin-top:16px;line-height:1.7">
      Click the button below to open the AI Fix Assistant — it will generate exact bash commands to fix each issue.
    </p>
    """

    html = _base_template(
        f"🚨 Critical Alert — {hostname}",
        content,
        f"{os.getenv('APP_URL','https://erprakashmijar.com')}/dashboard/index.html",
        "FIX NOW WITH AI →"
    )
    return send_email(to_email, f"🚨 CRITICAL: {len(critical)} critical issues found on {hostname}", html)


def send_scan_complete(to_email: str, user_name: str, scan_data: dict) -> dict:
    """Send scan completion notification with summary"""
    issues   = scan_data.get("issues", [])
    hostname = scan_data.get("hostname", scan_data.get("ip", "Unknown"))
    score    = scan_data.get("score", scan_data.get("security_score", 0))
    counts   = {}
    for i in issues:
        sev = i.get("severity", "low")
        counts[sev] = counts.get(sev, 0) + 1

    score_color = "#ff3b5c" if score < 50 else "#f59e0b" if score < 70 else "#00ff88"
    grade = "F" if score < 40 else "D" if score < 55 else "C" if score < 70 else "B" if score < 85 else "A"

    content = f"""
    <p style="color:#7aafc8;font-size:13px;line-height:1.7;margin:0 0 20px">
      Your security scan of <strong style="color:#c0dce8">{hostname}</strong> completed successfully.
      Here's your summary:
    </p>

    <!-- Score card -->
    <div style="text-align:center;margin:24px 0">
      <div style="display:inline-block;background:rgba(0,0,0,.3);border:2px solid {score_color}22;border-radius:12px;padding:24px 48px">
        <div style="font-size:56px;font-weight:700;color:{score_color};line-height:1">{score}</div>
        <div style="font-size:10px;color:#2a4a62;letter-spacing:3px;margin:8px 0 4px">SECURITY SCORE</div>
        <div style="font-size:22px;color:{score_color}">{grade}</div>
      </div>
    </div>

    <!-- Issue counts -->
    <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-bottom:20px">
      {''.join(f'<div style="background:{_severity_bg(s)};border:1px solid {_severity_color(s)}22;border-radius:6px;padding:12px;text-align:center"><div style="font-size:20px;color:{_severity_color(s)};font-weight:700">{counts.get(s,0)}</div><div style="font-size:10px;color:#2a4a62;letter-spacing:1px;margin-top:4px">{s.upper()}</div></div>' for s in ['critical','high','medium','low'])}
    </div>

    {'<div style="background:rgba(0,255,136,.05);border:1px solid rgba(0,255,136,.15);border-radius:6px;padding:14px;text-align:center"><div style="color:#00ff88;font-size:13px">✓ No critical or high issues found. Good job!</div></div>' if not counts.get("critical") and not counts.get("high") else '<p style="color:#ff8c42;font-size:12px;background:rgba(255,140,66,.06);border:1px solid rgba(255,140,66,.15);border-radius:6px;padding:14px">Action required: Use the AI Fix Assistant to generate exact commands to resolve these issues.</p>'}
    """

    html = _base_template(
        f"Scan Complete — {hostname}",
        content,
        f"{os.getenv('APP_URL','https://erprakashmijar.com')}/dashboard/index.html",
        "VIEW FULL REPORT →"
    )
    return send_email(to_email, f"PM::OFFSEC — Scan complete: {hostname} scored {score}/100", html)


def send_weekly_digest(to_email: str, user_name: str, stats: dict) -> dict:
    """Rich weekly security digest with trends"""
    total_scans  = stats.get("total_scans", 0)
    avg_score    = stats.get("avg_score", 0)
    best_device  = stats.get("best_device", "")
    worst_device = stats.get("worst_device", "")
    issues_fixed = stats.get("issues_fixed", 0)
    new_issues   = stats.get("new_issues", 0)
    open_incs    = stats.get("open_incidents", 0)
    week_start   = stats.get("week_start", "")

    score_color = "#ff3b5c" if avg_score < 50 else "#f59e0b" if avg_score < 70 else "#00ff88"
    trend_arrow = "↑" if stats.get("score_trend", 0) > 0 else "↓" if stats.get("score_trend", 0) < 0 else "→"
    trend_color = "#00ff88" if trend_arrow == "↑" else "#ff3b5c" if trend_arrow == "↓" else "#7aafc8"

    content = f"""
    <p style="color:#7aafc8;font-size:13px;line-height:1.7;margin:0 0 20px">
      Here's your PM::OFFSEC security summary for the week of <strong style="color:#c0dce8">{week_start}</strong>.
    </p>

    <!-- Stats row -->
    <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:24px">
      <div style="background:rgba(0,0,0,.3);border:1px solid rgba(0,255,136,.08);border-radius:8px;padding:16px;text-align:center">
        <div style="font-size:28px;color:{score_color};font-weight:700">{avg_score}</div>
        <div style="font-size:10px;color:#2a4a62;letter-spacing:2px;margin-top:4px">AVG SCORE</div>
        <div style="font-size:14px;color:{trend_color};margin-top:4px">{trend_arrow} {abs(stats.get('score_trend',0))} pts</div>
      </div>
      <div style="background:rgba(0,0,0,.3);border:1px solid rgba(0,255,136,.08);border-radius:8px;padding:16px;text-align:center">
        <div style="font-size:28px;color:#00d4ff;font-weight:700">{total_scans}</div>
        <div style="font-size:10px;color:#2a4a62;letter-spacing:2px;margin-top:4px">SCANS RUN</div>
      </div>
      <div style="background:rgba(0,0,0,.3);border:1px solid rgba(0,255,136,.08);border-radius:8px;padding:16px;text-align:center">
        <div style="font-size:28px;color:#00ff88;font-weight:700">{issues_fixed}</div>
        <div style="font-size:10px;color:#2a4a62;letter-spacing:2px;margin-top:4px">ISSUES FIXED</div>
      </div>
    </div>

    <!-- Highlights -->
    <div style="background:rgba(0,255,136,.03);border:1px solid rgba(0,255,136,.08);border-radius:6px;padding:18px;margin-bottom:16px">
      <div style="font-size:10px;color:#00ff88;letter-spacing:2px;margin-bottom:12px">WEEK HIGHLIGHTS</div>
      {''.join(f'<div style="display:flex;align-items:center;gap:10px;padding:7px 0;border-bottom:1px solid rgba(0,255,136,.05)"><span style="color:{c};font-size:14px">{icon}</span><span style="color:#c0dce8;font-size:12px">{text}</span></div>' for icon,c,text in [
        ("✓", "#00ff88", f"{issues_fixed} issues resolved this week"),
        ("⚠", "#f59e0b", f"{new_issues} new issues discovered"),
        ("📊", "#00d4ff", f"{total_scans} security scans completed"),
        ("🔴", "#ff3b5c", f"{open_incs} incidents currently open"),
        ("🏆", "#00ff88", f"Best device this week: {best_device or 'N/A'}"),
        ("⚡", "#ff8c42", f"Needs attention: {worst_device or 'N/A'}"),
      ])}
    </div>

    <!-- Tips -->
    <div style="background:rgba(0,212,255,.04);border:1px solid rgba(0,212,255,.1);border-radius:6px;padding:16px">
      <div style="font-size:10px;color:#00d4ff;letter-spacing:2px;margin-bottom:10px">💡 SECURITY TIP OF THE WEEK</div>
      <p style="color:#7aafc8;font-size:12px;line-height:1.7;margin:0">
        Enable automatic weekly scans in the dashboard to maintain continuous visibility into your security posture.
        Set up Slack webhook alerts so your team gets notified instantly when critical issues are found.
      </p>
    </div>
    """

    html = _base_template(
        f"Weekly Security Digest — {week_start}",
        content,
        f"{os.getenv('APP_URL','https://erprakashmijar.com')}/dashboard/index.html",
        "OPEN DASHBOARD →"
    )
    return send_email(to_email, f"PM::OFFSEC Weekly Digest — Avg score: {avg_score}/100", html)


def send_plan_expiry_warning(to_email: str, user_name: str, plan: str, days_left: int) -> dict:
    """Warn user their subscription is about to expire"""
    content = f"""
    <div style="background:rgba(245,158,11,.06);border:1px solid rgba(245,158,11,.2);border-radius:6px;padding:18px;margin-bottom:20px">
      <div style="font-size:10px;color:#f59e0b;letter-spacing:2px">⚠ SUBSCRIPTION EXPIRING SOON</div>
      <p style="color:#c0dce8;font-size:14px;margin:10px 0 0">
        Your <strong style="color:#f59e0b">{plan.upper()}</strong> plan expires in
        <strong style="color:#ff3b5c">{days_left} day{'s' if days_left != 1 else ''}</strong>.
      </p>
    </div>
    <p style="color:#7aafc8;font-size:13px;line-height:1.7">
      After expiry you'll be downgraded to the Free plan (3 devices, 10 scans/day).
      Renew now to keep your full access, scan history, and scheduled scans.
    </p>
    """
    html = _base_template(
        "Your Subscription is Expiring",
        content,
        f"{os.getenv('APP_URL','https://erprakashmijar.com')}/billing/pricing.html",
        "RENEW NOW →"
    )
    return send_email(to_email, f"PM::OFFSEC — Your {plan} plan expires in {days_left} days", html)


def send_new_device_alert(to_email: str, user_name: str, device_ip: str, hostname: str) -> dict:
    """Alert when a new unknown device is found on the network"""
    content = f"""
    <div style="background:rgba(255,59,92,.06);border:1px solid rgba(255,59,92,.15);border-radius:6px;padding:18px;margin-bottom:20px">
      <div style="font-size:10px;color:#ff3b5c;letter-spacing:2px">🔍 NEW DEVICE DISCOVERED</div>
      <p style="color:#c0dce8;font-size:14px;margin:10px 0 0">
        An unrecognized device appeared on your network at <strong style="color:#ff8c42">{device_ip}</strong>
        {f'(hostname: {hostname})' if hostname else ''} on {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}.
      </p>
    </div>
    <p style="color:#7aafc8;font-size:13px;line-height:1.7">
      If you don't recognize this device, it could be an unauthorized connection.
      Run a security scan on it immediately to assess the risk.
    </p>
    """
    html = _base_template(
        "New Device Detected on Network",
        content,
        f"{os.getenv('APP_URL','https://erprakashmijar.com')}/dashboard/index.html",
        "SCAN DEVICE NOW →"
    )
    return send_email(to_email, f"⚠ PM::OFFSEC — Unknown device found: {device_ip}", html)


def send_slack_alert(webhook_url: str, message: str, color: str = "#00ff88") -> dict:
    """Send alert to Slack webhook"""
    if not webhook_url:
        return {"ok": False, "error": "No webhook URL"}
    try:
        import httpx
        payload = {
            "attachments": [{
                "color": color,
                "text": message,
                "footer": "PM::OFFSEC Security Dashboard",
                "ts": int(datetime.utcnow().timestamp())
            }]
        }
        r = httpx.post(webhook_url, json=payload, timeout=10)
        return {"ok": r.status_code == 200}
    except Exception as e:
        return {"ok": False, "error": str(e)}
