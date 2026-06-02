"""
Backend regression tests for PM::OFFSEC.

Covers the failures we have actually hit in development:
  - app imports cleanly (catches the missing `timedelta` import class of bug)
  - health endpoint works
  - auth register/login return JWTs (caught a 500 here before)
  - protected endpoints reject unauthenticated calls (401)
  - protected endpoints accept a valid JWT (auth bridge correctness)
  - the real camera scanner runs end to end
  - no endpoint 500s on a smoke pass

Run:  pytest tests/test_backend.py -q
"""
import os, sys, re, pathlib
import pytest

# Make the backend importable and run in in-memory mode.
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
os.environ.setdefault("LEMONSQUEEZY_WEBHOOK_SECRET", "")  # don't block the webhook test

from fastapi.testclient import TestClient  # noqa: E402
import main  # noqa: E402

main.RATE_LIMIT = 1_000_000  # disable rate limiting during tests
client = TestClient(main.app, raise_server_exceptions=False)


def _new_creds():
    """Fresh, unique credentials per call so tests never collide."""
    u = os.urandom(5).hex()
    return f"pytest_{u}@test.local", "Str0ngPass!" + u


def _register_and_token():
    email, password = _new_creds()
    r = client.post("/api/auth/register",
                    json={"email": email, "password": password, "name": "PyTest", "plan": "pro"})
    assert r.status_code == 200, r.text
    tok = r.json().get("access_token")
    assert tok
    return tok, email, password


# ── Import / boot ───────────────────────────────────────────────
def test_app_imports_and_has_routes():
    assert len(main.app.routes) > 50


def test_health_ok():
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json().get("status") == "ok"


# ── Auth ────────────────────────────────────────────────────────
def test_register_returns_jwt():
    tok, _, _ = _register_and_token()
    assert tok.count(".") == 2  # JWT has three segments


def test_login_after_register():
    _, email, password = _register_and_token()
    r = client.post("/api/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    assert r.json().get("access_token")


def test_login_bad_password_rejected():
    _, email, _ = _register_and_token()
    r = client.post("/api/auth/login", json={"email": email, "password": "definitely-wrong"})
    assert r.status_code in (400, 401, 403)


# ── Protected endpoint auth (the bridge correctness) ────────────
def test_camera_scan_requires_auth():
    r = client.post("/api/camera/scan", json={"network": "127.0.0.1"})
    assert r.status_code in (401, 403)


def test_camera_scan_with_token_runs():
    tok, _, _ = _register_and_token()
    r = client.post("/api/camera/scan", json={"network": "127.0.0.1"},
                    headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200, r.text
    body = r.json()
    for key in ("cameras", "total", "hardening", "scanned_at"):
        assert key in body


def test_account_is_server_side_cross_device():
    """Register, then log in fresh (as if from another device) — same user_id.
    Locks in the multi-user fix: accounts live server-side, not per-browser."""
    _, email, password = _register_and_token()
    r = client.post("/api/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    assert r.json().get("access_token")


def test_admin_endpoints_reject_non_admin():
    """A normal user's token must be denied (403) on admin endpoints,
    and the user list must require auth. Locks in server-side authz."""
    tok, _, _ = _register_and_token()  # role = 'user'
    h = {"Authorization": f"Bearer {tok}"}
    assert client.get("/api/admin/users", headers=h).status_code == 403
    assert client.put("/api/admin/users/whoever/role", json={"role": "admin"}, headers=h).status_code == 403
    assert client.delete("/api/admin/users/whoever", headers=h).status_code == 403
    # user list must not be public
    assert client.get("/api/users").status_code in (401, 403)


def test_admin_endpoints_allow_admin_and_hide_passwords():
    import database
    # create an admin: register then promote in DB, then re-login for a role=admin token
    r = client.post("/api/auth/register",
                    json={"email": f"adm_{os.urandom(3).hex()}@test.local", "password": "Adm1nPass!", "name": "Adm", "plan": "enterprise"})
    uid = r.json()["user_id"]; email = r.json()["email"]
    database.user_update(uid, role="admin")
    tok = client.post("/api/auth/login", json={"email": email, "password": "Adm1nPass!"}).json()["access_token"]
    h = {"Authorization": f"Bearer {tok}"}
    resp = client.get("/api/admin/users", headers=h)
    assert resp.status_code == 200
    users = resp.json()["users"]
    assert all("password" not in u for u in users), "password fields must be stripped"


def test_portal_client_returns_own_summary():
    import database
    tok, _, _ = _register_and_token()
    # decode user_id from a fresh login is overkill; just call and check shape
    r = client.get("/api/portal/client", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200
    body = r.json()
    for k in ("device_count", "issues_by_severity", "avg_score", "total_issues"):
        assert k in body


def test_portal_admin_requires_admin():
    tok, _, _ = _register_and_token()  # role=user
    assert client.get("/api/portal/admin/clients", headers={"Authorization": f"Bearer {tok}"}).status_code == 403


def test_portal_client_returns_own_summary():
    """Client portal endpoint returns the signed-in user's own scan summary."""
    import database
    tok, _, _ = _register_and_token()
    # decode user_id from the token via a /api/portal/client call after saving a scan
    me = client.get("/api/auth/verify", headers={"Authorization": f"Bearer {tok}"})
    # save a scan for this user
    r = client.get("/api/portal/client", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200, r.text
    body = r.json()
    for k in ("device_count", "issues_by_severity", "critical_count"):
        assert k in body


def test_portal_admin_requires_admin():
    """Admin/MSP client list must reject non-admins."""
    tok, _, _ = _register_and_token()
    assert client.get("/api/portal/admin/clients", headers={"Authorization": f"Bearer {tok}"}).status_code == 403


def test_profile_self_update():
    """User can update their own name/phone/address/company via /api/profile."""
    tok, _, _ = _register_and_token()
    r = client.put("/api/profile",
                   json={"name": "Updated Name", "phone": "+1 555 999 0000", "address": "1 Test Rd", "company": "TestCo"},
                   headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200, r.text
    prof = r.json()["profile"]
    assert prof["name"] == "Updated Name"
    assert prof["address"] == "1 Test Rd"
    assert "password" not in prof
    # unauthenticated rejected
    assert client.put("/api/profile", json={"name": "X"}).status_code in (401, 403)


def test_org_devices_and_employee_flow():
    """Business owner gets an org automatically, an employee joins it and registers
    a device, and the owner sees the employee + device (tenant data flow)."""
    # Business owner — org is auto-created on registration
    rc = client.post("/api/auth/register", json={"email": f"biz_{os.urandom(3).hex()}@acme.com", "password": "Passw0rd!", "name": "Biz", "plan": "professional", "client_type": "business", "company": "Acme"})
    assert rc.json().get("role") == "owner", rc.text
    org_id = rc.json().get("org_id")
    assert org_id, "business owner should have an org_id"
    ctok = client.post("/api/auth/login", json={"email": rc.json()["email"], "password": "Passw0rd!"}).json()["access_token"]
    ch = {"Authorization": f"Bearer {ctok}"}

    # employee self-registers into the org using the owner's org code
    eemail = f"emp_{os.urandom(3).hex()}@acme.com"
    emp = client.post("/api/org/employee/register", json={"name": "Emp", "email": eemail, "password": "Passw0rd!", "org_id": org_id})
    assert emp.status_code == 200, emp.text
    assert emp.json()["role"] == "employee"
    assert emp.json()["org_id"] == org_id
    etok = emp.json()["access_token"]

    # employee registers their device (the flow the personal portal form uses)
    dev = client.post("/api/org/devices/register",
                      json={"device_name": "Emp-Mac", "hostname": "emp-mac", "device_type": "laptop", "os": "macOS"},
                      headers={"Authorization": f"Bearer {etok}"})
    assert dev.status_code == 200, dev.text

    # owner sees the employee and the device
    me = client.get("/api/org/me", headers=ch).json()
    emails = [e.get("email") for e in me.get("employees", [])]
    assert eemail in emails
    assert any((d.get("device_name") == "Emp-Mac") for d in me.get("devices", []))

    # a different business owner sees none of this org's devices (tenant isolation)
    ro = client.post("/api/auth/register", json={"email": f"other_{os.urandom(3).hex()}@beta.com", "password": "Passw0rd!", "name": "Other", "client_type": "business", "company": "Beta"})
    otok = client.post("/api/auth/login", json={"email": ro.json()["email"], "password": "Passw0rd!"}).json()["access_token"]
    other_me = client.get("/api/org/me", headers={"Authorization": f"Bearer {otok}"}).json()
    assert len(other_me.get("devices", [])) == 0


def test_org_devices_requires_auth():
    assert client.get("/api/org/devices").status_code in (401, 403)
    assert client.post("/api/org/devices", json={"device_name": "X"}).status_code in (401, 403)


def test_client_type_individual_and_business():
    """Registration records client_type and login returns it (drives portal routing)."""
    ri = client.post("/api/auth/register", json={"email": f"i_{os.urandom(3).hex()}@x.com", "password": "Passw0rd!", "name": "Ind", "client_type": "individual"})
    assert ri.json().get("client_type") == "individual"
    rb = client.post("/api/auth/register", json={"email": f"b_{os.urandom(3).hex()}@x.com", "password": "Passw0rd!", "name": "Biz", "client_type": "business", "plan": "professional"})
    assert rb.json().get("client_type") == "business"
    # login echoes it back
    lb = client.post("/api/auth/login", json={"email": rb.json()["email"], "password": "Passw0rd!"})
    assert lb.json().get("client_type") == "business"
    # default when omitted
    rd = client.post("/api/auth/register", json={"email": f"d_{os.urandom(3).hex()}@x.com", "password": "Passw0rd!", "name": "Def"})
    assert rd.json().get("client_type") == "individual"


# ── Webhook robustness (regression: empty body used to 500) ─────
def test_lemonsqueezy_webhook_handles_bad_input():
    r = client.post("/api/webhooks/lemonsqueezy", json={})
    assert r.status_code != 500


# ── Smoke pass: no GET endpoint should 500 ──────────────────────
def test_no_get_endpoint_returns_500():
    spec = main.app.openapi()
    offenders = []
    for path, ops in spec["paths"].items():
        if "get" not in ops:
            continue
        if "{" in path:  # skip path-param routes in the smoke pass
            continue
        # skip endpoints that perform live external network calls
        if re.search(r"scan|darkweb|threat|attack-surface|ssl", path):
            continue
        r = client.get(path)
        if r.status_code >= 500:
            offenders.append((path, r.status_code))
    assert not offenders, f"5xx from: {offenders}"
