"""
billing.py — Dual payment provider (Stripe + Lemon Squeezy)
Handles subscriptions, webhooks, and plan enforcement
"""
import os
import httpx
import stripe
from fastapi import HTTPException

# ── PLAN DEFINITIONS ────────────────────────────────────────────
PLANS = {
    "free": {
        "name": "Free",
        "price": 0,
        "devices": 3,
        "scans_per_day": 10,
        "ai_analysis": False,
        "email_alerts": False,
        "scheduled_scans": False,
        "pdf_reports": False,
        "history_days": 7,
        "network_discovery": False,
        "description": "Perfect for individuals learning security",
        "features": [
            "3 devices",
            "10 scans per day",
            "Basic security score",
            "TXT report export",
            "Community support"
        ]
    },
    "starter": {
        "name": "Starter",
        "price": 19,
        "devices": 10,
        "scans_per_day": 50,
        "ai_analysis": True,
        "email_alerts": True,
        "scheduled_scans": False,
        "pdf_reports": False,
        "history_days": 30,
        "network_discovery": True,
        "description": "For freelancers and small projects",
        "features": [
            "10 devices",
            "50 scans per day",
            "AI vulnerability analysis",
            "Email alerts",
            "Network discovery",
            "30-day scan history",
            "JSON + TXT export",
            "Email support"
        ],
        "stripe_price_id": os.getenv("STRIPE_STARTER_PRICE_ID", ""),
        "lemonsqueezy_variant_id": os.getenv("LS_STARTER_VARIANT_ID", ""),
    },
    "professional": {
        "name": "Professional",
        "price": 79,
        "devices": 50,
        "scans_per_day": 500,
        "ai_analysis": True,
        "email_alerts": True,
        "scheduled_scans": True,
        "pdf_reports": True,
        "history_days": 90,
        "network_discovery": True,
        "description": "For security professionals and agencies",
        "features": [
            "50 devices",
            "500 scans per day",
            "AI analysis + chat",
            "Scheduled automatic scans",
            "PDF executive reports",
            "Email alerts (instant)",
            "90-day history",
            "Network discovery",
            "Priority support"
        ],
        "stripe_price_id": os.getenv("STRIPE_PRO_PRICE_ID", ""),
        "lemonsqueezy_variant_id": os.getenv("LS_PRO_VARIANT_ID", ""),
    },
    "enterprise": {
        "name": "Enterprise",
        "price": 199,
        "devices": -1,  # unlimited
        "scans_per_day": -1,
        "ai_analysis": True,
        "email_alerts": True,
        "scheduled_scans": True,
        "pdf_reports": True,
        "history_days": 365,
        "network_discovery": True,
        "compliance_reports": True,
        "description": "For teams and businesses",
        "features": [
            "Unlimited devices",
            "Unlimited scans",
            "Full AI suite",
            "Scheduled scans (cron)",
            "Compliance reports (CIS)",
            "PDF + JSON + TXT export",
            "Email + webhook alerts",
            "1-year history",
            "Dedicated support",
            "Team accounts (5 seats)"
        ],
        "stripe_price_id": os.getenv("STRIPE_ENTERPRISE_PRICE_ID", ""),
        "lemonsqueezy_variant_id": os.getenv("LS_ENTERPRISE_VARIANT_ID", ""),
    }
}

# ── STRIPE ───────────────────────────────────────────────────────
def init_stripe():
    key = os.getenv("STRIPE_SECRET_KEY")
    if key:
        stripe.api_key = key
    return bool(key)

async def create_stripe_checkout(plan_key: str, user_email: str, user_id: str, success_url: str, cancel_url: str) -> str:
    """Create a Stripe checkout session and return the URL"""
    plan = PLANS.get(plan_key)
    if not plan or plan["price"] == 0:
        raise HTTPException(400, "Invalid plan for checkout")
    price_id = plan.get("stripe_price_id")
    if not price_id:
        raise HTTPException(400, "Stripe price ID not configured for this plan. Add STRIPE_STARTER_PRICE_ID etc. to .env")
    try:
        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            mode="subscription",
            customer_email=user_email,
            line_items=[{"price": price_id, "quantity": 1}],
            success_url=success_url + "?session_id={CHECKOUT_SESSION_ID}&provider=stripe&plan=" + plan_key,
            cancel_url=cancel_url,
            metadata={"user_id": user_id, "plan": plan_key},
            subscription_data={"metadata": {"user_id": user_id, "plan": plan_key}}
        )
        return session.url
    except stripe.error.StripeError as e:
        raise HTTPException(400, f"Stripe error: {str(e)}")

def handle_stripe_webhook(payload: bytes, sig_header: str) -> dict:
    """Verify and parse a Stripe webhook"""
    secret = os.getenv("STRIPE_WEBHOOK_SECRET")
    if not secret:
        raise HTTPException(400, "STRIPE_WEBHOOK_SECRET not configured")
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, secret)
    except stripe.error.SignatureVerificationError:
        raise HTTPException(400, "Invalid Stripe signature")
    return {"type": event.type, "data": event.data.object}

async def cancel_stripe_subscription(subscription_id: str) -> bool:
    """Cancel a Stripe subscription at period end"""
    try:
        stripe.Subscription.modify(subscription_id, cancel_at_period_end=True)
        return True
    except:
        return False

# ── LEMON SQUEEZY ────────────────────────────────────────────────
async def create_lemonsqueezy_checkout(plan_key: str, user_email: str, user_id: str) -> str:
    """Create a Lemon Squeezy checkout URL"""
    plan = PLANS.get(plan_key)
    if not plan or plan["price"] == 0:
        raise HTTPException(400, "Invalid plan")
    variant_id = plan.get("lemonsqueezy_variant_id")
    api_key = os.getenv("LEMONSQUEEZY_API_KEY")
    store_id = os.getenv("LEMONSQUEEZY_STORE_ID")
    if not all([variant_id, api_key, store_id]):
        raise HTTPException(400, "Lemon Squeezy not fully configured. Add LS_STARTER_VARIANT_ID, LEMONSQUEEZY_API_KEY, LEMONSQUEEZY_STORE_ID to .env")
    try:
        async with httpx.AsyncClient() as client:
            r = await client.post(
                "https://api.lemonsqueezy.com/v1/checkouts",
                headers={"Authorization": f"Bearer {api_key}", "Accept": "application/vnd.api+json", "Content-Type": "application/vnd.api+json"},
                json={
                    "data": {
                        "type": "checkouts",
                        "attributes": {
                            "checkout_data": {"email": user_email, "custom": {"user_id": user_id, "plan": plan_key}},
                            "product_options": {"redirect_url": os.getenv("APP_URL", "http://localhost:8000") + "/billing/success?provider=lemonsqueezy&plan=" + plan_key}
                        },
                        "relationships": {
                            "store": {"data": {"type": "stores", "id": store_id}},
                            "variant": {"data": {"type": "variants", "id": variant_id}}
                        }
                    }
                }
            )
        data = r.json()
        return data["data"]["attributes"]["url"]
    except Exception as e:
        raise HTTPException(400, f"Lemon Squeezy error: {str(e)}")

def handle_lemonsqueezy_webhook(payload: dict, signature: str, raw_body: bytes) -> dict:
    """Verify and parse a Lemon Squeezy webhook"""
    import hmac, hashlib
    secret = os.getenv("LEMONSQUEEZY_WEBHOOK_SECRET", "")
    if secret:
        expected = hmac.new(secret.encode(), raw_body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature):
            raise HTTPException(400, "Invalid Lemon Squeezy signature")
    event_type = payload.get("meta", {}).get("event_name", "")
    return {"type": event_type, "data": payload.get("data", {}), "meta": payload.get("meta", {})}

# ── PLAN ENFORCEMENT ─────────────────────────────────────────────
def check_plan_limit(user_plan: str, resource: str, current_count: int = 0) -> bool:
    """Check if user can use a feature based on their plan. Returns True if allowed."""
    plan = PLANS.get(user_plan, PLANS["free"])
    if resource == "devices":
        limit = plan["devices"]
        return limit == -1 or current_count < limit
    elif resource == "scans_per_day":
        limit = plan["scans_per_day"]
        return limit == -1 or current_count < limit
    elif resource in ("ai_analysis", "email_alerts", "scheduled_scans", "pdf_reports", "network_discovery"):
        return plan.get(resource, False)
    return False

def get_plan_info(plan_key: str) -> dict:
    return PLANS.get(plan_key, PLANS["free"])

# ═══════════════════════════════════════════════════════════════
# FEATURE 4 — COMPLETE PAYMENT PROCESSING
# ═══════════════════════════════════════════════════════════════

import json, time
from datetime import datetime, timedelta
from database import subscription_save, plan_set, plan_get, user_get_by_email

# ── TRIAL SYSTEM ────────────────────────────────────────────────
TRIAL_DAYS = 14

def start_trial(user_id: str, plan_key: str = "starter") -> dict:
    """Give new users a 14-day free trial of Starter"""
    expires = datetime.utcnow() + timedelta(days=TRIAL_DAYS)
    sub_data = {
        "plan": plan_key,
        "status": "trial",
        "trial_end": expires.isoformat(),
        "current_period_end": expires.isoformat(),
    }
    subscription_save(user_id, sub_data)
    plan_set(user_id, plan_key)
    return {"ok": True, "trial_end": expires.isoformat(), "plan": plan_key}

def check_trial_status(user_id: str) -> dict:
    """Check if a trial is still active"""
    from database import subscription_get
    sub = subscription_get(user_id)
    if sub.get("status") != "trial":
        return {"on_trial": False}
    trial_end = sub.get("trial_end")
    if not trial_end:
        return {"on_trial": False}
    try:
        end_dt = datetime.fromisoformat(trial_end.replace("Z",""))
        days_left = (end_dt - datetime.utcnow()).days
        active = days_left >= 0
        if not active:
            # Trial expired — downgrade to free
            plan_set(user_id, "free")
            subscription_save(user_id, {"plan": "free", "status": "inactive"})
        return {"on_trial": active, "days_left": max(0, days_left), "trial_end": trial_end}
    except:
        return {"on_trial": False}

# ── INVOICE GENERATION ───────────────────────────────────────────
def generate_invoice(user_id: str, plan: str, amount: float,
                     provider: str, transaction_id: str) -> dict:
    """Generate invoice data (HTML printable)"""
    inv_num = f"INV-{datetime.utcnow().strftime('%Y%m')}-{transaction_id[:8].upper()}"
    return {
        "invoice_number": inv_num,
        "date": datetime.utcnow().strftime("%Y-%m-%d"),
        "due_date": datetime.utcnow().strftime("%Y-%m-%d"),
        "user_id": user_id,
        "plan": plan,
        "amount": amount,
        "provider": provider,
        "transaction_id": transaction_id,
        "status": "paid",
        "items": [{
            "description": f"PM::OFFSEC {plan.title()} Plan — Monthly Subscription",
            "quantity": 1,
            "unit_price": amount,
            "total": amount
        }],
        "subtotal": amount,
        "tax": 0,
        "total": amount,
        "generated_at": datetime.utcnow().isoformat()
    }

def generate_invoice_html(invoice: dict, user_name: str, user_email: str) -> str:
    """Generate printable HTML invoice"""
    items_html = "".join(f"""
    <tr>
      <td style="padding:10px 0;border-bottom:1px solid #eee;font-size:13px">{item['description']}</td>
      <td style="padding:10px 0;border-bottom:1px solid #eee;text-align:center;font-size:13px">{item['quantity']}</td>
      <td style="padding:10px 0;border-bottom:1px solid #eee;text-align:right;font-size:13px">${item['unit_price']:.2f}</td>
      <td style="padding:10px 0;border-bottom:1px solid #eee;text-align:right;font-size:13px">${item['total']:.2f}</td>
    </tr>""" for item in invoice.get("items", []))

    return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"/>
<title>Invoice {invoice['invoice_number']}</title>
<style>
  body{{font-family:'Courier New',monospace;max-width:800px;margin:40px auto;padding:0 20px;color:#1a1a2e}}
  .header{{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:40px;border-bottom:2px solid #00aa55;padding-bottom:20px}}
  .logo{{font-size:24px;color:#1a1a2e;letter-spacing:3px}}.logo span{{color:#00aa55}}
  .inv-num{{text-align:right;font-size:12px;color:#666}}
  .inv-num strong{{font-size:22px;color:#1a1a2e;display:block;margin-bottom:4px}}
  .row{{display:flex;gap:40px;margin-bottom:30px}}
  .col{{flex:1}}.label{{font-size:10px;color:#999;letter-spacing:2px;margin-bottom:6px}}
  .value{{font-size:13px;color:#1a1a2e;line-height:1.6}}
  table{{width:100%;border-collapse:collapse;margin:20px 0}}
  th{{font-size:10px;letter-spacing:2px;color:#999;padding:8px 0;border-bottom:2px solid #1a1a2e;text-align:left}}
  th:last-child,th:nth-last-child(2){{text-align:right}}
  .total-row{{display:flex;justify-content:flex-end;margin-top:16px}}
  .total-box{{background:#f5f5f5;border-radius:6px;padding:16px 24px;min-width:200px;text-align:right}}
  .total-label{{font-size:11px;color:#999;letter-spacing:1px}}
  .total-amount{{font-size:28px;font-weight:700;color:#00aa55;margin-top:4px}}
  .badge{{display:inline-block;background:#00aa55;color:#fff;font-size:11px;letter-spacing:2px;padding:4px 12px;border-radius:3px}}
  .footer{{margin-top:40px;padding-top:16px;border-top:1px solid #eee;font-size:11px;color:#999;text-align:center}}
  @media print{{body{{margin:0}}.footer{{page-break-inside:avoid}}}}
</style></head>
<body>
<div class="header">
  <div>
    <div class="logo">PM<span>::</span>OFFSEC</div>
    <div style="font-size:11px;color:#999;letter-spacing:1px;margin-top:4px">SECURITY DASHBOARD</div>
    <div style="font-size:11px;color:#999;margin-top:8px">erprakashmijar.com<br>contact@erprakashmijar.com</div>
  </div>
  <div class="inv-num">
    <strong>{invoice['invoice_number']}</strong>
    <div>Date: {invoice['date']}</div>
    <div>Status: <span class="badge">PAID</span></div>
  </div>
</div>

<div class="row">
  <div class="col"><div class="label">BILLED TO</div>
    <div class="value"><strong>{user_name}</strong><br>{user_email}</div>
  </div>
  <div class="col"><div class="label">PAYMENT</div>
    <div class="value">Provider: {invoice['provider'].title()}<br>
    Transaction: {invoice['transaction_id'][:16]}...</div>
  </div>
</div>

<table>
  <thead><tr>
    <th>DESCRIPTION</th>
    <th style="text-align:center">QTY</th>
    <th style="text-align:right">UNIT PRICE</th>
    <th style="text-align:right">TOTAL</th>
  </tr></thead>
  <tbody>{items_html}</tbody>
</table>

<div class="total-row">
  <div class="total-box">
    <div class="total-label">AMOUNT PAID</div>
    <div class="total-amount">${invoice['total']:.2f}</div>
    <div style="font-size:11px;color:#999;margin-top:4px">USD / month</div>
  </div>
</div>

<div class="footer">
  PM::OFFSEC Security Dashboard · erprakashmijar.com<br>
  Thank you for your subscription. This invoice was generated automatically.
</div>
</body></html>"""

# ── WEBHOOK PROCESSORS ───────────────────────────────────────────
def process_stripe_event(event_type: str, event_data: dict) -> dict:
    """Process Stripe webhook events and update database"""
    result = {"handled": False, "action": ""}

    if event_type == "checkout.session.completed":
        user_id  = event_data.get("metadata", {}).get("user_id", "")
        plan_key = event_data.get("metadata", {}).get("plan", "starter")
        email    = event_data.get("customer_email", "")
        sub_id   = event_data.get("subscription", "")
        cust_id  = event_data.get("customer", "")

        if user_id:
            subscription_save(user_id, {
                "plan": plan_key, "status": "active",
                "stripe_customer": cust_id, "stripe_sub": sub_id,
                "current_period_end": None
            })
            plan_set(user_id, plan_key)
            result = {"handled": True, "action": f"upgraded_{plan_key}", "user_id": user_id}

    elif event_type == "customer.subscription.updated":
        sub_id = event_data.get("id", "")
        status = event_data.get("status", "")
        period_end = event_data.get("current_period_end")
        if period_end:
            period_end = datetime.fromtimestamp(period_end).isoformat()
        # Find user by stripe subscription ID
        result = {"handled": True, "action": f"sub_updated_{status}"}

    elif event_type == "customer.subscription.deleted":
        sub_id = event_data.get("id", "")
        cust_id = event_data.get("customer", "")
        # Downgrade to free
        result = {"handled": True, "action": "subscription_cancelled"}

    elif event_type == "invoice.payment_failed":
        cust_id = event_data.get("customer", "")
        result = {"handled": True, "action": "payment_failed"}

    elif event_type == "invoice.paid":
        cust_id = event_data.get("customer", "")
        amount = event_data.get("amount_paid", 0) / 100
        result = {"handled": True, "action": "invoice_paid", "amount": amount}

    return result

def process_ls_event(event_type: str, event_data: dict, meta: dict) -> dict:
    """Process Lemon Squeezy webhook events"""
    result = {"handled": False, "action": ""}

    custom = meta.get("custom_data", {})
    user_id  = custom.get("user_id", "")
    plan_key = custom.get("plan", "starter")

    if event_type == "order_created":
        if user_id:
            sub_id   = str(event_data.get("id", ""))
            order_id = str(event_data.get("attributes", {}).get("order_number", ""))
            subscription_save(user_id, {
                "plan": plan_key, "status": "active",
                "ls_sub": sub_id, "ls_order": order_id
            })
            plan_set(user_id, plan_key)
            result = {"handled": True, "action": f"upgraded_{plan_key}", "user_id": user_id}

    elif event_type == "subscription_cancelled":
        if user_id:
            plan_set(user_id, "free")
            subscription_save(user_id, {"plan": "free", "status": "cancelled"})
            result = {"handled": True, "action": "subscription_cancelled"}

    return result

# ── UPGRADE / DOWNGRADE ──────────────────────────────────────────
def downgrade_to_free(user_id: str, reason: str = "cancelled") -> bool:
    """Downgrade user to free plan"""
    plan_set(user_id, "free")
    subscription_save(user_id, {
        "plan": "free", "status": "inactive",
        "downgraded_at": datetime.utcnow().isoformat(),
        "downgrade_reason": reason
    })
    return True

def get_upgrade_url(user_id: str, current_plan: str, target_plan: str,
                    provider: str, user_email: str, app_url: str) -> dict:
    """Get the correct upgrade URL based on plan and provider"""
    if current_plan == target_plan:
        return {"ok": False, "error": "Already on this plan"}
    if PLANS.get(target_plan, {}).get("price", 0) == 0:
        return {"ok": False, "error": "Cannot upgrade to free"}
    return {
        "ok": True,
        "checkout_url": f"{app_url}/billing/pricing.html?upgrade={target_plan}&from={current_plan}",
        "provider": provider,
        "plan": target_plan,
        "price": PLANS.get(target_plan, {}).get("price", 0)
    }
