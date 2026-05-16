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
        "devices": 1,
        "scans_per_day": 1,
        "ai_analysis": False,
        "email_alerts": False,
        "scheduled_scans": False,
        "pdf_reports": False,
        "history_days": 7,
        "network_discovery": False,
        "description": "Perfect for individuals learning security",
        "features": [
            "1 device",
            "1 scan per day",
            "Basic security score",
            "TXT report export",
            "Community support"
        ]
    },
    "starter": {
        "name": "Starter",
        "price": 19,
        "devices": 5,
        "scans_per_day": 10,
        "ai_analysis": True,
        "email_alerts": True,
        "scheduled_scans": False,
        "pdf_reports": False,
        "history_days": 30,
        "network_discovery": True,
        "description": "For freelancers and small projects",
        "features": [
            "5 devices",
            "10 scans per day",
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
        "devices": 25,
        "scans_per_day": 100,
        "ai_analysis": True,
        "email_alerts": True,
        "scheduled_scans": True,
        "pdf_reports": True,
        "history_days": 90,
        "network_discovery": True,
        "description": "For security professionals and agencies",
        "features": [
            "25 devices",
            "100 scans per day",
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
