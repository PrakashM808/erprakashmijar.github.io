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
