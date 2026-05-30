# PM::OFFSEC — Deployment & API Key Setup Guide

This guide covers every way to deploy the platform and exactly which API keys
to set. It is written specifically for this codebase (FastAPI backend +
PostgreSQL + static HTML/JS frontend).

---

## 1. Architecture (what you are deploying)

There are two deployable pieces:

| Piece | What it is | Where it lives | Hosting |
|---|---|---|---|
| **Frontend** | Static HTML/CSS/JS (`index.html`, `login.html`, `dashboard/`, `client/`, `admin/`, `assets/`) | repo root | GitHub Pages (current), or Netlify/Vercel |
| **Backend** | FastAPI app (`backend/`) + PostgreSQL | `backend/` | Railway (current), or any Docker host |

They talk over HTTPS. The frontend auto-detects the backend URL: on
`localhost` it uses `http://localhost:8000`; in production it uses your
Railway URL (`https://pm-offsec-backend-production.up.railway.app`). To point
at a different backend, set `localStorage.pm_railway_url` or the API URL in the
dashboard's API Settings.

**Golden rule:** one backend, one database, one auth system. Never split these.

---

## 2. The two services must be SEPARATE on your host

Your recent `PORT=5432` problem came from the web app and the database getting
entangled. On Railway (or anywhere), you need **two distinct services**:

1. **Web service** — runs the FastAPI app (this is what serves HTTP).
2. **PostgreSQL service** — Railway's managed Postgres (or any Postgres).

The web service connects to the database via the `DATABASE_URL` variable. The
web service must **not** inherit the database's `PORT` (5432). The included
`backend/start.sh` now refuses to bind to 5432 as a safety net, but the correct
setup keeps them separate.

---

## 3. Deployment methods

### Method A — Railway (current setup, recommended)

Railway builds from `backend/Dockerfile` (configured in `backend/railway.json`).

1. **Create the project** at railway.app → New Project.
2. **Add PostgreSQL**: New → Database → Add PostgreSQL. This creates a
   separate Postgres service with its own `DATABASE_URL`.
3. **Add the backend service**: New → GitHub Repo → select your repo. Set the
   service's **Root Directory** to `backend` (so it finds the Dockerfile).
4. **Link the database**: on the backend service → Variables → add
   `DATABASE_URL` as a reference: `${{Postgres.DATABASE_URL}}`. (Use the
   "Add Reference" option — do not paste the raw value.)
5. **Set the environment variables** from section 4 below.
6. **Do NOT manually set `PORT`.** Let Railway inject it. `start.sh` handles the
   rest and will fall back to 8000 if anything invalid arrives.
7. **Deploy.** Watch the logs — you should see
   `Launching uvicorn on 0.0.0.0:<port>` where `<port>` is NOT 5432.
8. **Generate a public domain**: Settings → Networking → Generate Domain (or
   attach a custom one). Confirm `GET /api/health` returns `{"status":"ok"}`.

### Method B — Any Docker host (Render, Fly.io, DigitalOcean, a VPS)

The app is a standard Docker container. From `backend/`:

```bash
docker build -t pmoffsec-backend .
docker run -p 8000:8000 --env-file .env pmoffsec-backend
```

- **Render**: New → Web Service → Docker → root dir `backend`. Add a Render
  PostgreSQL instance, set `DATABASE_URL`, set the env vars. Render injects
  `PORT` automatically.
- **Fly.io**: `fly launch` in `backend/`, `fly postgres create`, `fly postgres
  attach` (sets `DATABASE_URL`), `fly secrets set KEY=value ...`, `fly deploy`.
- **VPS (Ubuntu)**: install Docker + a managed/self-hosted Postgres, run the
  container behind Nginx/Caddy for TLS, set env vars via `--env-file`.

### Method C — Local development

```bash
cd backend
cp .env.example .env          # then fill in values
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

Without `DATABASE_URL`, the app runs in **in-memory mode** — fine for testing,
but all data is lost on restart. Set `DATABASE_URL` for persistence.

Frontend locally: serve the repo root with any static server, e.g.
`python -m http.server 5500`, then open `http://localhost:5500`.

### Frontend deployment

- **GitHub Pages (current)**: push the repo; Pages serves the root. Custom
  domain `erprakashmijar.com` is configured via `CNAME`/DNS. Static only — no
  build step.
- **Netlify / Vercel**: drag-and-drop the repo or connect it; set the publish
  directory to the repo root. No build command needed (plain HTML/JS).

After deploying the frontend, make sure the backend's CORS allows your frontend
origin. It currently allows `erprakashmijar.com` and `www.erprakashmijar.com`
(in `backend/main.py`). Add any new domain there.

---

## 4. Environment variables & API keys

Set these on your **backend** service (Railway → Variables, or `.env` locally).
Only the first two are strictly required to run; everything else unlocks a
feature and degrades gracefully when absent.

### Required

| Variable | What it does | Where to get it |
|---|---|---|
| `JWT_SECRET_KEY` | Signs login tokens. **Critical** — without it a known default is used and tokens can be forged. | Generate: `python -c "import secrets; print(secrets.token_urlsafe(48))"` |
| `DATABASE_URL` | PostgreSQL connection. Without it, data is in-memory and lost on restart. | Railway Postgres → reference `${{Postgres.DATABASE_URL}}` |

### Core features

| Variable | Feature | Where to get it | Cost |
|---|---|---|---|
| `ANTHROPIC_API_KEY` | AI Analysis / AI assistant | console.anthropic.com → API Keys | Pay-as-you-go (~$0.03/analysis) |
| `SENDGRID_API_KEY` | Email alerts, reports, OTP | sendgrid.com → Settings → API Keys | Free <100/day, then ~$20/mo |
| `ALERT_FROM_EMAIL` / `ALERT_FROM_NAME` | Sender identity for emails | your verified sender in SendGrid | — |
| `APP_URL` | Links in emails point back to your app | `https://erprakashmijar.com` | — |

### Billing (pick ONE provider)

**Stripe** (dashboard.stripe.com → Developers → API keys):

| Variable | Notes |
|---|---|
| `STRIPE_SECRET_KEY` | `sk_live_...` (or `sk_test_...` for testing) |
| `STRIPE_PUBLISHABLE_KEY` | `pk_live_...` |
| `STRIPE_WEBHOOK_SECRET` | `whsec_...` from the webhook endpoint you create |
| `STRIPE_STARTER_PRICE_ID` / `STRIPE_PRO_PRICE_ID` / `STRIPE_ENTERPRISE_PRICE_ID` | `price_...` for each plan you create in Stripe → Products |

Point your Stripe webhook at `https://<backend>/api/webhooks/stripe`.

**Lemon Squeezy** (app.lemonsqueezy.com — simpler, handles tax/VAT):

| Variable | Notes |
|---|---|
| `LEMONSQUEEZY_API_KEY` | Settings → API |
| `LEMONSQUEEZY_STORE_ID` | your store id |
| `LEMONSQUEEZY_WEBHOOK_SECRET` | from the webhook you create |
| `LS_STARTER_VARIANT_ID` / `LS_PRO_VARIANT_ID` / `LS_ENTERPRISE_VARIANT_ID` | product variant ids |

### Threat intelligence (all optional, free tiers exist)

| Variable | Service | Free tier |
|---|---|---|
| `HIBP_API_KEY` | Have I Been Pwned (dark-web/breach checks) | ~$3.50/mo (paid) |
| `ABUSEIPDB_API_KEY` | AbuseIPDB (IP reputation) | 1,000 checks/day |
| `VIRUSTOTAL_API_KEY` | VirusTotal (file/URL/IP scans) | 4 lookups/min |
| `SHODAN_API_KEY` | Shodan (exposure lookups) | limited |
| `NVD_API_KEY` | NIST NVD (CVE data) | free, raises rate limit |

CISA KEV (known-exploited CVEs) needs no key — it's a free public feed.

### Optional integrations

| Variable(s) | Service |
|---|---|
| `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` | "Sign in with GitHub" (github.com → Settings → Developer settings → OAuth Apps; callback `https://<backend>/api/auth/github/callback`) |
| `TWILIO_ACCOUNT_SID` / `TWILIO_AUTH_TOKEN` / `TWILIO_PHONE_NUMBER` | SMS alerts (twilio.com) |
| `WAZUH_URL` / `WAZUH_USER` / `WAZUH_PASSWORD` | Wazuh SIEM integration |
| `SPLUNK_URL` / `SPLUNK_TOKEN` / `SPLUNK_HEC_URL` / `SPLUNK_HEC_TOKEN` | Splunk SIEM integration |

---

## 5. Post-deploy checklist

1. **Health check**: `GET https://<backend>/api/health` → `{"status":"ok"}`.
2. **Logs are clean**: uvicorn on a non-5432 port, no "Invalid HTTP request" spam.
3. **Database persists**: register a test account, redeploy, confirm you can
   still log in (proves `DATABASE_URL` is wired, not in-memory).
4. **Promote your admin account** (run once against your Postgres):
   ```sql
   UPDATE users SET role='admin' WHERE email='you@erprakashmijar.com';
   ```
   Then log in — you should land on the admin portal.
5. **Two-device test**: register on one device, log in on another → same
   account (proves server-side auth).
6. **CORS**: from the live frontend, confirm login/scan calls succeed (no CORS
   errors in the browser console).
7. **Frontend cache**: after deploying frontend changes, hard-refresh once (the
   service worker is network-first for CSS/JS, so it self-updates afterward).

---

## 6. Minimum viable launch

To go live with the smallest set of keys:

1. `JWT_SECRET_KEY` (generate one)
2. `DATABASE_URL` (Railway Postgres reference)
3. `ANTHROPIC_API_KEY` (for AI features)
4. `SENDGRID_API_KEY` + `ALERT_FROM_EMAIL` (for account/alert emails)

Add billing (Stripe or Lemon Squeezy) when you start charging, and threat-intel
keys as you turn those features from demo to live. Everything not set simply
stays inactive — the app won't crash for a missing optional key.
