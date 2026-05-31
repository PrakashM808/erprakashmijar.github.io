"""
database.py — PM::OFFSEC PostgreSQL Database Layer
Handles all persistent storage: users, scans, incidents, agreements, alerts
Falls back to in-memory if DATABASE_URL not set (dev mode)
"""
import os, json, uuid
from datetime import datetime, date
from typing import Optional, List, Dict, Any
from contextlib import contextmanager

DATABASE_URL = os.getenv("DATABASE_URL", "")

# ── Try to import psycopg2, fall back to in-memory ──────────────
try:
    import psycopg2
    import psycopg2.extras
    from psycopg2.pool import ThreadedConnectionPool
    POSTGRES_AVAILABLE = bool(DATABASE_URL)
except ImportError:
    POSTGRES_AVAILABLE = False

print(f"[DB] Mode: {'PostgreSQL' if POSTGRES_AVAILABLE else 'In-Memory (localStorage fallback)'}")

# ── Connection Pool ──────────────────────────────────────────────
_pool = None

def get_pool():
    global _pool, POSTGRES_AVAILABLE
    if _pool is None and POSTGRES_AVAILABLE:
        try:
            _pool = ThreadedConnectionPool(
                minconn=1, maxconn=5,
                dsn=DATABASE_URL,
                connect_timeout=5,
                cursor_factory=psycopg2.extras.RealDictCursor
            )
            print("[DB] Connection pool created")
        except Exception as e:
            print(f"[DB] Pool creation failed: {e}")
            POSTGRES_AVAILABLE = False  # Disable further attempts after failure
            _pool = None
    return _pool

@contextmanager
def get_db():
    """Context manager for database connections"""
    pool = get_pool()
    if pool is None:
        yield None
        return
    conn = pool.getconn()
    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        pool.putconn(conn)

# ── In-memory fallback stores ────────────────────────────────────
_mem = {
    "users": {},          # user_id -> user dict
    "scans": [],          # list of scan result dicts
    "scan_counts": {},    # "user_id:YYYY-MM-DD" -> int
    "scan_history": {},   # ip -> list of history points
    "incidents": [],      # list of incident dicts
    "agreements": [],     # list of agreement dicts
    "alert_prefs": {},    # user_id -> prefs dict
    "user_plans": {},     # user_id -> plan_key
    "user_subs": {},      # user_id -> subscription dict
    "iocs": [],           # list of IOC dicts
    "scheduled_scans": [],# list of scheduled scan dicts
}

# ═══════════════════════════════════════════════════════════════
# SCHEMA INITIALIZATION
# ═══════════════════════════════════════════════════════════════

SCHEMA_SQL = """
-- Users table
CREATE TABLE IF NOT EXISTS users (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    email       TEXT UNIQUE NOT NULL,
    password    TEXT NOT NULL,
    role        TEXT DEFAULT 'user',
    plan        TEXT DEFAULT 'free',
    status      TEXT DEFAULT 'active',
    avatar      TEXT,
    company     TEXT,
    phone       TEXT,
    address     TEXT,
    notes       TEXT,
    org_id      TEXT,
    client_type TEXT DEFAULT 'individual',
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    last_login  TIMESTAMPTZ,
    login_count INTEGER DEFAULT 0,
    meta        JSONB DEFAULT '{}'
);

-- Scan results table
CREATE TABLE IF NOT EXISTS scans (
    id          TEXT PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    user_id     TEXT REFERENCES users(id) ON DELETE CASCADE,
    ip          TEXT,
    hostname    TEXT,
    os          TEXT,
    score       INTEGER,
    severity    TEXT,
    issues      JSONB DEFAULT '[]',
    open_ports  JSONB DEFAULT '[]',
    firewall    JSONB DEFAULT '{}',
    ssh_config  JSONB DEFAULT '{}',
    packages    JSONB DEFAULT '[]',
    raw_data    JSONB DEFAULT '{}',
    scan_type   TEXT DEFAULT 'local',
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- Org devices: employees & their laptops, owned by a client (org_id = client's user id)
CREATE TABLE IF NOT EXISTS org_devices (
    id            TEXT PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    org_id        TEXT,
    employee_name TEXT,
    employee_email TEXT,
    device_name   TEXT,
    device_type   TEXT DEFAULT 'laptop',
    os            TEXT,
    last_score    INTEGER,
    status        TEXT DEFAULT 'active',
    added_by      TEXT DEFAULT 'client',
    created_at    TIMESTAMPTZ DEFAULT NOW()
);

-- Scan counts (for rate limiting)
CREATE TABLE IF NOT EXISTS scan_counts (
    user_id     TEXT,
    scan_date   DATE DEFAULT CURRENT_DATE,
    count       INTEGER DEFAULT 0,
    PRIMARY KEY (user_id, scan_date)
);

-- Incidents table
CREATE TABLE IF NOT EXISTS incidents (
    id              TEXT PRIMARY KEY,
    user_id         TEXT REFERENCES users(id) ON DELETE CASCADE,
    title           TEXT NOT NULL,
    severity        TEXT DEFAULT 'medium',
    status          TEXT DEFAULT 'open',
    description     TEXT,
    affected_devices JSONB DEFAULT '[]',
    mitre_techniques JSONB DEFAULT '[]',
    iocs            JSONB DEFAULT '[]',
    tags            JSONB DEFAULT '[]',
    timeline        JSONB DEFAULT '[]',
    assigned_to     TEXT,
    created_by      TEXT,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW(),
    resolved_at     TIMESTAMPTZ
);

-- Organizations table (multi-tenant)
CREATE TABLE IF NOT EXISTS organizations (
    id           TEXT PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    name         TEXT NOT NULL,
    owner_id     TEXT,
    plan         TEXT DEFAULT 'starter',
    status       TEXT DEFAULT 'active',
    max_devices  INTEGER DEFAULT 10,
    max_employees INTEGER DEFAULT 25,
    industry     TEXT,
    country      TEXT DEFAULT 'NP',
    logo_url     TEXT,
    settings     JSONB DEFAULT '{}',
    created_at   TIMESTAMPTZ DEFAULT NOW(),
    updated_at   TIMESTAMPTZ DEFAULT NOW()
);

-- Employee invites
CREATE TABLE IF NOT EXISTS invites (
    id           TEXT PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    org_id       TEXT REFERENCES organizations(id) ON DELETE CASCADE,
    invited_by   TEXT REFERENCES users(id) ON DELETE SET NULL,
    email        TEXT NOT NULL,
    name         TEXT,
    role         TEXT DEFAULT 'employee',
    token        TEXT UNIQUE NOT NULL,
    status       TEXT DEFAULT 'pending',
    expires_at   TIMESTAMPTZ DEFAULT (NOW() + INTERVAL '7 days'),
    created_at   TIMESTAMPTZ DEFAULT NOW()
);

-- Org devices v2 with full tracking
CREATE TABLE IF NOT EXISTS org_devices_v2 (
    id              TEXT PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    org_id          TEXT REFERENCES organizations(id) ON DELETE CASCADE,
    user_id         TEXT REFERENCES users(id) ON DELETE SET NULL,
    hostname        TEXT,
    device_name     TEXT,
    device_type     TEXT DEFAULT 'laptop',
    os              TEXT,
    os_version      TEXT,
    ip_address      TEXT,
    mac_address     TEXT,
    agent_token     TEXT UNIQUE DEFAULT gen_random_uuid()::TEXT,
    agent_version   TEXT,
    last_score      INTEGER DEFAULT 0,
    last_seen       TIMESTAMPTZ,
    status          TEXT DEFAULT 'active',
    tags            JSONB DEFAULT '[]',
    meta            JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- Refresh tokens for JWT refresh
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id           TEXT PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    user_id      TEXT REFERENCES users(id) ON DELETE CASCADE,
    token        TEXT UNIQUE NOT NULL,
    expires_at   TIMESTAMPTZ DEFAULT (NOW() + INTERVAL '30 days'),
    created_at   TIMESTAMPTZ DEFAULT NOW()
);

-- Activity/audit per org
CREATE TABLE IF NOT EXISTS org_activity (
    id           TEXT PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    org_id       TEXT,
    user_id      TEXT,
    action       TEXT NOT NULL,
    target       TEXT,
    detail       TEXT,
    ip_address   TEXT,
    created_at   TIMESTAMPTZ DEFAULT NOW()
);

-- Agreements table
CREATE TABLE IF NOT EXISTS agreements (
    id              TEXT PRIMARY KEY,
    user_id         TEXT REFERENCES users(id) ON DELETE SET NULL,
    name            TEXT NOT NULL,
    title           TEXT,
    org             TEXT,
    email           TEXT,
    phone           TEXT,
    address         TEXT,
    engagement_type TEXT,
    environment     TEXT,
    start_date      DATE,
    end_date        DATE,
    scope           TEXT,
    notes           TEXT,
    signature       TEXT,
    emergency       TEXT,
    ip_address      TEXT,
    signed_at       TIMESTAMPTZ DEFAULT NOW()
);

-- Alert preferences
CREATE TABLE IF NOT EXISTS alert_prefs (
    user_id         TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    email           TEXT,
    enabled         BOOLEAN DEFAULT TRUE,
    on_critical     BOOLEAN DEFAULT TRUE,
    on_high         BOOLEAN DEFAULT TRUE,
    on_medium       BOOLEAN DEFAULT FALSE,
    weekly_report   BOOLEAN DEFAULT TRUE,
    slack_webhook   TEXT,
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

-- User plans and subscriptions
CREATE TABLE IF NOT EXISTS user_plans (
    user_id         TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    plan_key        TEXT DEFAULT 'free',
    stripe_customer TEXT,
    stripe_sub      TEXT,
    ls_customer     TEXT,
    ls_sub          TEXT,
    sub_status      TEXT DEFAULT 'inactive',
    current_period_end TIMESTAMPTZ,
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

-- IOC database
CREATE TABLE IF NOT EXISTS iocs (
    id          TEXT PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    user_id     TEXT REFERENCES users(id) ON DELETE CASCADE,
    type        TEXT NOT NULL,
    value       TEXT NOT NULL,
    severity    TEXT DEFAULT 'medium',
    description TEXT,
    source      TEXT,
    tags        JSONB DEFAULT '[]',
    hits        INTEGER DEFAULT 0,
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    updated_at  TIMESTAMPTZ DEFAULT NOW()
);

-- Scheduled scans
CREATE TABLE IF NOT EXISTS scheduled_scans (
    id          TEXT PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    user_id     TEXT REFERENCES users(id) ON DELETE CASCADE,
    name        TEXT,
    target_ip   TEXT,
    scan_type   TEXT DEFAULT 'local',
    cron_expr   TEXT,
    enabled     BOOLEAN DEFAULT TRUE,
    last_run    TIMESTAMPTZ,
    next_run    TIMESTAMPTZ,
    run_count   INTEGER DEFAULT 0,
    meta        JSONB DEFAULT '{}',
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_scans_user     ON scans(user_id);
CREATE INDEX IF NOT EXISTS idx_scans_ip       ON scans(ip);
CREATE INDEX IF NOT EXISTS idx_scans_created  ON scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_user ON incidents(user_id);
CREATE INDEX IF NOT EXISTS idx_iocs_user      ON iocs(user_id);
CREATE INDEX IF NOT EXISTS idx_users_email    ON users(email);
"""

def init_db():
    """Create all tables if they don't exist"""
    if not POSTGRES_AVAILABLE:
        print("[DB] Running in memory mode — no PostgreSQL")
        return False
    try:
        with get_db() as conn:
            if conn is None:
                return False
            cur = conn.cursor()
            cur.execute(SCHEMA_SQL)
            # Idempotent migration: ensure newer columns exist on pre-existing tables.
            try:
                cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS address TEXT")
                cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS org_id TEXT")
                cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS client_type TEXT DEFAULT 'individual'")
            except Exception as mig_e:
                print(f"[DB] column migration note: {mig_e}")
            print("[DB] Schema initialized ✅")
            return True
    except Exception as e:
        print(f"[DB] Schema init failed: {e}")
        return False

# ═══════════════════════════════════════════════════════════════
# USER OPERATIONS
# ═══════════════════════════════════════════════════════════════

def user_create(user_id: str, name: str, email: str, password: str,
                role: str = "user", plan: str = "free",
                company: str = "", phone: str = "", client_type: str = "individual") -> dict:
    user = {
        "id": user_id, "name": name, "email": email.lower(),
        "password": password, "role": role, "plan": plan,
        "status": "active", "company": company, "phone": phone,
        "client_type": client_type, "org_id": user_id,
        "created": datetime.utcnow().isoformat(),
        "loginCount": 0
    }
    if POSTGRES_AVAILABLE:
        try:
            with get_db() as conn:
                cur = conn.cursor()
                cur.execute("""
                    INSERT INTO users (id, name, email, password, role, plan, company, phone, client_type, org_id)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT (email) DO NOTHING
                    RETURNING id
                """, (user_id, name, email.lower(), password, role, plan, company, phone, client_type, user_id))
                return user
        except Exception as e:
            print(f"[DB] user_create error: {e}")
    _mem["users"][user_id] = user
    return user

def user_get_by_email(email: str) -> Optional[dict]:
    if POSTGRES_AVAILABLE:
        try:
            with get_db() as conn:
                cur = conn.cursor()
                cur.execute("SELECT * FROM users WHERE email=%s", (email.lower(),))
                row = cur.fetchone()
                if row:
                    return dict(row)
        except Exception as e:
            print(f"[DB] user_get_by_email error: {e}")
    for u in _mem["users"].values():
        if u.get("email", "").lower() == email.lower():
            return u
    return None

def user_get(user_id: str) -> Optional[dict]:
    if POSTGRES_AVAILABLE:
        try:
            with get_db() as conn:
                cur = conn.cursor()
                cur.execute("SELECT * FROM users WHERE id=%s", (user_id,))
                row = cur.fetchone()
                if row:
                    return dict(row)
        except Exception as e:
            print(f"[DB] user_get error: {e}")
    return _mem["users"].get(user_id)

def user_update(user_id: str, **kwargs) -> bool:
    allowed = {"name","email","role","plan","status","company","phone","address","notes","org_id","client_type","last_login","login_count"}
    kwargs = {k:v for k,v in kwargs.items() if k in allowed}
    if not kwargs:
        return False
    if POSTGRES_AVAILABLE:
        try:
            with get_db() as conn:
                cur = conn.cursor()
                sets = ", ".join(f"{k}=%s" for k in kwargs)
                vals = list(kwargs.values()) + [user_id]
                cur.execute(f"UPDATE users SET {sets} WHERE id=%s", vals)
                return True
        except Exception as e:
            print(f"[DB] user_update error: {e}")
    if user_id in _mem["users"]:
        _mem["users"][user_id].update(kwargs)
        return True
    return False

def user_delete(user_id: str) -> bool:
    if POSTGRES_AVAILABLE:
        try:
            with get_db() as conn:
                cur = conn.cursor()
                cur.execute("DELETE FROM users WHERE id=%s", (user_id,))
                return True
        except Exception as e:
            print(f"[DB] user_delete error: {e}")
    if user_id in _mem["users"]:
        del _mem["users"][user_id]
        return True
    return False

# ── Org device operations (client → employees → laptops) ──────────
def org_device_add(org_id: str, data: dict) -> dict:
    import uuid as _uuid
    dev = {
        "id": _uuid.uuid4().hex[:16], "org_id": org_id,
        "employee_name": data.get("employee_name",""),
        "employee_email": (data.get("employee_email","") or "").lower(),
        "device_name": data.get("device_name",""),
        "device_type": data.get("device_type","laptop"),
        "os": data.get("os",""), "last_score": data.get("last_score"),
        "status": data.get("status","active"), "added_by": data.get("added_by","client"),
        "created_at": datetime.utcnow().isoformat(),
    }
    if POSTGRES_AVAILABLE:
        try:
            with get_db() as conn:
                cur = conn.cursor()
                cur.execute("""INSERT INTO org_devices
                    (id, org_id, employee_name, employee_email, device_name, device_type, os, last_score, status, added_by)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (dev["id"], org_id, dev["employee_name"], dev["employee_email"], dev["device_name"],
                     dev["device_type"], dev["os"], dev["last_score"], dev["status"], dev["added_by"]))
            return dev
        except Exception as e:
            print(f"[DB] org_device_add error: {e}")
    _mem.setdefault("org_devices", {})[dev["id"]] = dev
    return dev

def org_devices_get(org_id: str) -> list:
    if POSTGRES_AVAILABLE:
        try:
            with get_db() as conn:
                cur = conn.cursor()
                cur.execute("SELECT id, org_id, employee_name, employee_email, device_name, device_type, os, last_score, status, added_by, created_at FROM org_devices WHERE org_id=%s ORDER BY created_at DESC", (org_id,))
                cols = [d[0] for d in cur.description]
                return [dict(zip(cols, row)) for row in cur.fetchall()]
        except Exception as e:
            print(f"[DB] org_devices_get error: {e}")
    return [d for d in _mem.get("org_devices", {}).values() if d.get("org_id") == org_id]

def org_device_delete(device_id: str, org_id: str) -> bool:
    if POSTGRES_AVAILABLE:
        try:
            with get_db() as conn:
                cur = conn.cursor()
                cur.execute("DELETE FROM org_devices WHERE id=%s AND org_id=%s", (device_id, org_id))
                return True
        except Exception as e:
            print(f"[DB] org_device_delete error: {e}")
    d = _mem.get("org_devices", {}).get(device_id)
    if d and d.get("org_id") == org_id:
        del _mem["org_devices"][device_id]
        return True
    return False

def user_record_login(user_id: str):
    now = datetime.utcnow().isoformat()
    if POSTGRES_AVAILABLE:
        try:
            with get_db() as conn:
                cur = conn.cursor()
                cur.execute("""
                    UPDATE users SET last_login=%s, login_count=login_count+1
                    WHERE id=%s
                """, (now, user_id))
                return
        except Exception as e:
            print(f"[DB] user_record_login error: {e}")
    if user_id in _mem["users"]:
        u = _mem["users"][user_id]
        u["lastLogin"] = now
        u["loginCount"] = u.get("loginCount", 0) + 1

def users_get_all() -> List[dict]:
    if POSTGRES_AVAILABLE:
        try:
            with get_db() as conn:
                cur = conn.cursor()
                cur.execute("SELECT * FROM users ORDER BY created_at DESC")
                return [dict(r) for r in cur.fetchall()]
        except Exception as e:
            print(f"[DB] users_get_all error: {e}")
    return list(_mem["users"].values())

# ═══════════════════════════════════════════════════════════════
# SCAN OPERATIONS
# ═══════════════════════════════════════════════════════════════

def scan_save(user_id: str, result: dict) -> str:
    scan_id = str(uuid.uuid4())
    if POSTGRES_AVAILABLE:
        try:
            with get_db() as conn:
                cur = conn.cursor()
                cur.execute("""
                    INSERT INTO scans
                    (id, user_id, ip, hostname, os, score, severity,
                     issues, open_ports, firewall, ssh_config, packages, raw_data, scan_type)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """, (
                    scan_id, user_id,
                    result.get("ip",""), result.get("hostname",""),
                    result.get("os",""), result.get("score",0),
                    result.get("severity","low"),
                    json.dumps(result.get("issues",[])),
                    json.dumps(result.get("open_ports",[])),
                    json.dumps(result.get("firewall",{})),
                    json.dumps(result.get("ssh_config",{})),
                    json.dumps(result.get("packages",[])),
                    json.dumps(result), "local"
                ))
                # Update history
                _update_scan_history_pg(conn, result)
                return scan_id
        except Exception as e:
            print(f"[DB] scan_save error: {e}")
    # In-memory fallback
    result["id"] = scan_id
    result["user_id"] = user_id
    result["created_at"] = datetime.utcnow().isoformat()
    _mem["scans"].append(result)
    _update_scan_history_mem(result)
    return scan_id

def _update_scan_history_pg(conn, result: dict):
    ip = result.get("ip","")
    if not ip:
        return
    try:
        cur = conn.cursor()
        # Upsert a history entry — store last 90 days
        cur.execute("""
            INSERT INTO scans (id, ip, score, hostname, scan_type, created_at)
            VALUES (gen_random_uuid()::TEXT, %s, %s, %s, 'history', NOW())
        """, (ip, result.get("score",0), result.get("hostname","")))
    except Exception:
        pass

def _update_scan_history_mem(result: dict):
    ip = result.get("ip","")
    if not ip:
        return
    hist = _mem["scan_history"].setdefault(ip, [])
    hist.append({
        "date": datetime.utcnow().strftime("%Y-%m-%d"),
        "score": result.get("score", 0),
        "hostname": result.get("hostname",""),
        "timestamp": datetime.utcnow().isoformat()
    })
    _mem["scan_history"][ip] = hist[-90:]  # keep 90 days

def scan_get_history(ip: str) -> List[dict]:
    if POSTGRES_AVAILABLE:
        try:
            with get_db() as conn:
                cur = conn.cursor()
                cur.execute("""
                    SELECT created_at::DATE as date, score, hostname
                    FROM scans WHERE ip=%s AND scan_type != 'history'
                    ORDER BY created_at DESC LIMIT 90
                """, (ip,))
                return [dict(r) for r in cur.fetchall()]
        except Exception as e:
            print(f"[DB] scan_get_history error: {e}")
    return _mem["scan_history"].get(ip, [])

def scan_get_all_history() -> dict:
    if POSTGRES_AVAILABLE:
        try:
            with get_db() as conn:
                cur = conn.cursor()
                cur.execute("""
                    SELECT ip, json_agg(
                        json_build_object('date', created_at::DATE, 'score', score)
                        ORDER BY created_at DESC
                    ) as history
                    FROM scans WHERE scan_type != 'history'
                    GROUP BY ip
                """)
                return {row["ip"]: row["history"] for row in cur.fetchall()}
        except Exception as e:
            print(f"[DB] scan_get_all_history error: {e}")
    return _mem["scan_history"]

def scan_get_recent(user_id: str, limit: int = 10) -> List[dict]:
    if POSTGRES_AVAILABLE:
        try:
            with get_db() as conn:
                cur = conn.cursor()
                cur.execute("""
                    SELECT * FROM scans WHERE user_id=%s AND scan_type != 'history'
                    ORDER BY created_at DESC LIMIT %s
                """, (user_id, limit))
                return [dict(r) for r in cur.fetchall()]
        except Exception as e:
            print(f"[DB] scan_get_recent error: {e}")
    return [s for s in _mem["scans"] if s.get("user_id") == user_id][:limit]

# ═══════════════════════════════════════════════════════════════
# SCAN COUNT / RATE LIMITING
# ═══════════════════════════════════════════════════════════════

def scan_count_increment(user_id: str) -> int:
    today = date.today().isoformat()
    if POSTGRES_AVAILABLE:
        try:
            with get_db() as conn:
                cur = conn.cursor()
                cur.execute("""
                    INSERT INTO scan_counts (user_id, scan_date, count)
                    VALUES (%s, %s, 1)
                    ON CONFLICT (user_id, scan_date)
                    DO UPDATE SET count = scan_counts.count + 1
                    RETURNING count
                """, (user_id, today))
                return cur.fetchone()["count"]
        except Exception as e:
            print(f"[DB] scan_count_increment error: {e}")
    key = f"{user_id}:{today}"
    _mem["scan_counts"][key] = _mem["scan_counts"].get(key, 0) + 1
    return _mem["scan_counts"][key]

def scan_count_get_today(user_id: str) -> int:
    today = date.today().isoformat()
    if POSTGRES_AVAILABLE:
        try:
            with get_db() as conn:
                cur = conn.cursor()
                cur.execute("""
                    SELECT count FROM scan_counts WHERE user_id=%s AND scan_date=%s
                """, (user_id, today))
                row = cur.fetchone()
                return row["count"] if row else 0
        except Exception as e:
            print(f"[DB] scan_count_get_today error: {e}")
    key = f"{user_id}:{today}"
    return _mem["scan_counts"].get(key, 0)

# ═══════════════════════════════════════════════════════════════
# INCIDENT OPERATIONS
# ═══════════════════════════════════════════════════════════════

def incident_create(user_id: str, data: dict) -> dict:
    inc_id = data.get("id") or str(uuid.uuid4())[:8].upper()
    now = datetime.utcnow().isoformat()
    incident = {**data, "id": inc_id, "user_id": user_id,
                "created_at": now, "updated_at": now}
    if POSTGRES_AVAILABLE:
        try:
            with get_db() as conn:
                cur = conn.cursor()
                cur.execute("""
                    INSERT INTO incidents
                    (id, user_id, title, severity, status, description,
                     affected_devices, mitre_techniques, iocs, tags, timeline,
                     assigned_to, created_by)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """, (
                    inc_id, user_id,
                    data.get("title",""), data.get("severity","medium"),
                    data.get("status","open"), data.get("description",""),
                    json.dumps(data.get("affected_devices",[])),
                    json.dumps(data.get("mitre_techniques",[])),
                    json.dumps(data.get("iocs",[])),
                    json.dumps(data.get("tags",[])),
                    json.dumps(data.get("timeline",[])),
                    data.get("assigned_to",""), data.get("created_by","")
                ))
                return incident
        except Exception as e:
            print(f"[DB] incident_create error: {e}")
    _mem["incidents"].append(incident)
    return incident

def incident_get_all(user_id: str) -> List[dict]:
    if POSTGRES_AVAILABLE:
        try:
            with get_db() as conn:
                cur = conn.cursor()
                cur.execute("""
                    SELECT * FROM incidents WHERE user_id=%s
                    ORDER BY created_at DESC
                """, (user_id,))
                return [dict(r) for r in cur.fetchall()]
        except Exception as e:
            print(f"[DB] incident_get_all error: {e}")
    return [i for i in _mem["incidents"] if i.get("user_id") == user_id]

def incident_update(incident_id: str, user_id: str, data: dict) -> bool:
    now = datetime.utcnow().isoformat()
    if POSTGRES_AVAILABLE:
        try:
            with get_db() as conn:
                cur = conn.cursor()
                cur.execute("""
                    UPDATE incidents SET
                        title=%s, severity=%s, status=%s, description=%s,
                        assigned_to=%s, timeline=%s, updated_at=%s
                    WHERE id=%s AND user_id=%s
                """, (
                    data.get("title"), data.get("severity"), data.get("status"),
                    data.get("description"), data.get("assigned_to"),
                    json.dumps(data.get("timeline",[])), now,
                    incident_id, user_id
                ))
                return True
        except Exception as e:
            print(f"[DB] incident_update error: {e}")
    for i, inc in enumerate(_mem["incidents"]):
        if inc["id"] == incident_id and inc.get("user_id") == user_id:
            _mem["incidents"][i] = {**inc, **data, "updated_at": now}
            return True
    return False

# ═══════════════════════════════════════════════════════════════
# AGREEMENT OPERATIONS
# ═══════════════════════════════════════════════════════════════

def agreement_save(user_id: Optional[str], data: dict) -> str:
    agr_id = data.get("id") or "AGR-" + str(uuid.uuid4())[:8].upper()
    if POSTGRES_AVAILABLE:
        try:
            with get_db() as conn:
                cur = conn.cursor()
                cur.execute("""
                    INSERT INTO agreements
                    (id, user_id, name, title, org, email, phone, address,
                     engagement_type, environment, start_date, end_date,
                     scope, notes, signature, emergency, ip_address)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """, (
                    agr_id, user_id,
                    data.get("name",""), data.get("title",""),
                    data.get("org",""), data.get("email",""),
                    data.get("phone",""), data.get("address",""),
                    data.get("type",""), data.get("env",""),
                    data.get("start") or None, data.get("end") or None,
                    data.get("scope",""), data.get("notes",""),
                    data.get("signature",""), data.get("emergency",""),
                    data.get("ip","")
                ))
                return agr_id
        except Exception as e:
            print(f"[DB] agreement_save error: {e}")
    agr = {**data, "id": agr_id, "user_id": user_id,
           "timestamp": datetime.utcnow().isoformat()}
    _mem["agreements"].append(agr)
    return agr_id

def agreements_get_all(user_id: Optional[str] = None) -> List[dict]:
    if POSTGRES_AVAILABLE:
        try:
            with get_db() as conn:
                cur = conn.cursor()
                if user_id:
                    cur.execute("SELECT * FROM agreements WHERE user_id=%s ORDER BY signed_at DESC", (user_id,))
                else:
                    cur.execute("SELECT * FROM agreements ORDER BY signed_at DESC")
                return [dict(r) for r in cur.fetchall()]
        except Exception as e:
            print(f"[DB] agreements_get_all error: {e}")
    if user_id:
        return [a for a in _mem["agreements"] if a.get("user_id") == user_id]
    return _mem["agreements"]

# ═══════════════════════════════════════════════════════════════
# ALERT PREFERENCES
# ═══════════════════════════════════════════════════════════════

def alert_prefs_set(user_id: str, prefs: dict) -> bool:
    if POSTGRES_AVAILABLE:
        try:
            with get_db() as conn:
                cur = conn.cursor()
                cur.execute("""
                    INSERT INTO alert_prefs
                    (user_id, email, enabled, on_critical, on_high, on_medium,
                     weekly_report, slack_webhook)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT (user_id) DO UPDATE SET
                        email=EXCLUDED.email, enabled=EXCLUDED.enabled,
                        on_critical=EXCLUDED.on_critical, on_high=EXCLUDED.on_high,
                        on_medium=EXCLUDED.on_medium,
                        weekly_report=EXCLUDED.weekly_report,
                        slack_webhook=EXCLUDED.slack_webhook,
                        updated_at=NOW()
                """, (
                    user_id, prefs.get("email",""), prefs.get("enabled", True),
                    prefs.get("on_critical", True), prefs.get("on_high", True),
                    prefs.get("on_medium", False), prefs.get("weekly_report", True),
                    prefs.get("slack_webhook","")
                ))
                return True
        except Exception as e:
            print(f"[DB] alert_prefs_set error: {e}")
    _mem["alert_prefs"][user_id] = prefs
    return True

def alert_prefs_get(user_id: str) -> dict:
    if POSTGRES_AVAILABLE:
        try:
            with get_db() as conn:
                cur = conn.cursor()
                cur.execute("SELECT * FROM alert_prefs WHERE user_id=%s", (user_id,))
                row = cur.fetchone()
                if row:
                    return dict(row)
        except Exception as e:
            print(f"[DB] alert_prefs_get error: {e}")
    return _mem["alert_prefs"].get(user_id, {"enabled": True})

# ═══════════════════════════════════════════════════════════════
# USER PLANS
# ═══════════════════════════════════════════════════════════════

def plan_set(user_id: str, plan_key: str, **kwargs) -> bool:
    if POSTGRES_AVAILABLE:
        try:
            with get_db() as conn:
                cur = conn.cursor()
                cur.execute("""
                    INSERT INTO user_plans (user_id, plan_key)
                    VALUES (%s, %s)
                    ON CONFLICT (user_id) DO UPDATE SET
                        plan_key=EXCLUDED.plan_key, updated_at=NOW()
                """, (user_id, plan_key))
                # Also update the users table
                cur.execute("UPDATE users SET plan=%s WHERE id=%s", (plan_key, user_id))
                return True
        except Exception as e:
            print(f"[DB] plan_set error: {e}")
    _mem["user_plans"][user_id] = plan_key
    if user_id in _mem["users"]:
        _mem["users"][user_id]["plan"] = plan_key
    return True

def plan_get(user_id: str) -> str:
    if POSTGRES_AVAILABLE:
        try:
            with get_db() as conn:
                cur = conn.cursor()
                cur.execute("SELECT plan FROM users WHERE id=%s", (user_id,))
                row = cur.fetchone()
                if row:
                    return row["plan"] or "free"
        except Exception as e:
            print(f"[DB] plan_get error: {e}")
    return _mem["user_plans"].get(user_id, "free")

def subscription_save(user_id: str, sub_data: dict) -> bool:
    if POSTGRES_AVAILABLE:
        try:
            with get_db() as conn:
                cur = conn.cursor()
                cur.execute("""
                    INSERT INTO user_plans
                    (user_id, plan_key, stripe_customer, stripe_sub,
                     ls_customer, ls_sub, sub_status, current_period_end)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT (user_id) DO UPDATE SET
                        plan_key=EXCLUDED.plan_key,
                        stripe_customer=EXCLUDED.stripe_customer,
                        stripe_sub=EXCLUDED.stripe_sub,
                        ls_customer=EXCLUDED.ls_customer,
                        ls_sub=EXCLUDED.ls_sub,
                        sub_status=EXCLUDED.sub_status,
                        current_period_end=EXCLUDED.current_period_end,
                        updated_at=NOW()
                """, (
                    user_id, sub_data.get("plan","free"),
                    sub_data.get("stripe_customer",""),
                    sub_data.get("stripe_sub",""),
                    sub_data.get("ls_customer",""),
                    sub_data.get("ls_sub",""),
                    sub_data.get("status","inactive"),
                    sub_data.get("current_period_end")
                ))
                # Update plan on users table
                cur.execute("UPDATE users SET plan=%s WHERE id=%s",
                           (sub_data.get("plan","free"), user_id))
                return True
        except Exception as e:
            print(f"[DB] subscription_save error: {e}")
    _mem["user_subs"][user_id] = sub_data
    return True

def subscription_get(user_id: str) -> dict:
    if POSTGRES_AVAILABLE:
        try:
            with get_db() as conn:
                cur = conn.cursor()
                cur.execute("SELECT * FROM user_plans WHERE user_id=%s", (user_id,))
                row = cur.fetchone()
                if row:
                    return dict(row)
        except Exception as e:
            print(f"[DB] subscription_get error: {e}")
    return _mem["user_subs"].get(user_id, {})

# ═══════════════════════════════════════════════════════════════
# IOC OPERATIONS
# ═══════════════════════════════════════════════════════════════

def ioc_add(user_id: str, data: dict) -> dict:
    ioc_id = str(uuid.uuid4())
    ioc = {**data, "id": ioc_id, "user_id": user_id,
           "hits": 0, "created_at": datetime.utcnow().isoformat()}
    if POSTGRES_AVAILABLE:
        try:
            with get_db() as conn:
                cur = conn.cursor()
                cur.execute("""
                    INSERT INTO iocs (id, user_id, type, value, severity, description, source, tags)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                """, (
                    ioc_id, user_id,
                    data.get("type",""), data.get("value",""),
                    data.get("severity","medium"), data.get("description",""),
                    data.get("source","manual"), json.dumps(data.get("tags",[]))
                ))
                return ioc
        except Exception as e:
            print(f"[DB] ioc_add error: {e}")
    _mem["iocs"].append(ioc)
    return ioc

def iocs_get_all(user_id: str) -> List[dict]:
    if POSTGRES_AVAILABLE:
        try:
            with get_db() as conn:
                cur = conn.cursor()
                cur.execute("SELECT * FROM iocs WHERE user_id=%s ORDER BY created_at DESC", (user_id,))
                return [dict(r) for r in cur.fetchall()]
        except Exception as e:
            print(f"[DB] iocs_get_all error: {e}")
    return [i for i in _mem["iocs"] if i.get("user_id") == user_id]

# ═══════════════════════════════════════════════════════════════
# ANALYTICS
# ═══════════════════════════════════════════════════════════════

def get_dashboard_stats(user_id: str) -> dict:
    """Get summary stats for a user's dashboard"""
    if POSTGRES_AVAILABLE:
        try:
            with get_db() as conn:
                cur = conn.cursor()
                # Total scans
                cur.execute("SELECT COUNT(*) as total FROM scans WHERE user_id=%s AND scan_type!='history'", (user_id,))
                total_scans = cur.fetchone()["total"]
                # Avg score
                cur.execute("SELECT AVG(score) as avg FROM scans WHERE user_id=%s AND scan_type!='history'", (user_id,))
                avg_score = round(cur.fetchone()["avg"] or 0)
                # Open incidents
                cur.execute("SELECT COUNT(*) as open FROM incidents WHERE user_id=%s AND status='open'", (user_id,))
                open_incidents = cur.fetchone()["open"]
                # Total issues found
                cur.execute("SELECT SUM(jsonb_array_length(issues)) as total FROM scans WHERE user_id=%s AND scan_type!='history'", (user_id,))
                total_issues = cur.fetchone()["total"] or 0
                return {
                    "total_scans": total_scans,
                    "avg_score": avg_score,
                    "open_incidents": open_incidents,
                    "total_issues": total_issues
                }
        except Exception as e:
            print(f"[DB] get_dashboard_stats error: {e}")
    # Fallback
    user_scans = [s for s in _mem["scans"] if s.get("user_id") == user_id]
    return {
        "total_scans": len(user_scans),
        "avg_score": round(sum(s.get("score",0) for s in user_scans) / max(len(user_scans),1)),
        "open_incidents": len([i for i in _mem["incidents"] if i.get("user_id")==user_id and i.get("status")=="open"]),
        "total_issues": sum(len(s.get("issues",[])) for s in user_scans)
    }

def get_score_history(user_id: str, days: int = 30) -> List[dict]:
    """Get score trend over time for charts"""
    if POSTGRES_AVAILABLE:
        try:
            with get_db() as conn:
                cur = conn.cursor()
                cur.execute("""
                    SELECT created_at::DATE as date, AVG(score)::INTEGER as score
                    FROM scans
                    WHERE user_id=%s AND scan_type!='history'
                    AND created_at > NOW() - INTERVAL '%s days'
                    GROUP BY created_at::DATE
                    ORDER BY date ASC
                """, (user_id, days))
                return [dict(r) for r in cur.fetchall()]
        except Exception as e:
            print(f"[DB] get_score_history error: {e}")
    user_scans = [s for s in _mem["scans"] if s.get("user_id") == user_id]
    return [{"date": s.get("created_at","")[:10], "score": s.get("score",0)} for s in user_scans[-30:]]

    # Scan results with full findings history
    cur.execute("""
        CREATE TABLE IF NOT EXISTS scan_results (
            id          TEXT PRIMARY KEY,
            user_id     TEXT NOT NULL,
            target_host TEXT NOT NULL,
            target_ip   TEXT,
            scan_type   TEXT NOT NULL DEFAULT 'remote',
            score       INTEGER DEFAULT 0,
            grade       TEXT DEFAULT 'F',
            findings    JSONB DEFAULT '[]',
            open_ports  JSONB DEFAULT '[]',
            ssh_config  JSONB DEFAULT '{}',
            os_info     TEXT,
            duration_s  FLOAT DEFAULT 0,
            created_at  TIMESTAMP DEFAULT NOW()
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_sr_user ON scan_results(user_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_sr_host ON scan_results(target_host)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_sr_date ON scan_results(created_at)")

    # Full audit trail
    cur.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id          BIGSERIAL PRIMARY KEY,
            user_id     TEXT,
            user_email  TEXT,
            action      TEXT NOT NULL,
            resource    TEXT,
            detail      TEXT,
            ip_address  TEXT,
            user_agent  TEXT,
            status      TEXT DEFAULT 'ok',
            created_at  TIMESTAMP DEFAULT NOW()
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_date ON audit_log(created_at)")

    # GDPR deletion requests
    cur.execute("""
        CREATE TABLE IF NOT EXISTS deletion_requests (
            id           TEXT PRIMARY KEY,
            user_id      TEXT NOT NULL,
            user_email   TEXT NOT NULL,
            requested_at TIMESTAMP DEFAULT NOW(),
            completed_at TIMESTAMP,
            status       TEXT DEFAULT 'pending'
        )
    """)

    # Per-user rate limits
    cur.execute("""
        CREATE TABLE IF NOT EXISTS rate_limits (
            key          TEXT NOT NULL,
            window_start TIMESTAMP NOT NULL,
            count        INTEGER DEFAULT 1,
            PRIMARY KEY  (key, window_start)
        )
    """)


# ── Organization helpers ─────────────────────────────────────────────────────

def org_create(name: str, owner_id: str, plan: str = 'starter') -> dict:
    with get_db() as conn:
        if not conn:
            oid = 'org-' + owner_id[:8]
            _mem.setdefault('orgs', {})[oid] = {
                'id': oid, 'name': name, 'owner_id': owner_id, 'plan': plan,
                'status': 'active', 'max_devices': 10, 'max_employees': 25
            }
            return _mem['orgs'][oid]
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO organizations (name, owner_id, plan)
            VALUES (%s, %s, %s) RETURNING *
        """, (name, owner_id, plan))
        return dict(zip([d[0] for d in cur.description], cur.fetchone()))

def org_get(org_id: str) -> dict:
    with get_db() as conn:
        if not conn:
            return _mem.get('orgs', {}).get(org_id)
        cur = conn.cursor()
        cur.execute("SELECT * FROM organizations WHERE id = %s", (org_id,))
        row = cur.fetchone()
        return dict(zip([d[0] for d in cur.description], row)) if row else None

def org_get_by_owner(owner_id: str) -> dict:
    with get_db() as conn:
        if not conn:
            for o in _mem.get('orgs', {}).values():
                if o.get('owner_id') == owner_id:
                    return o
            return None
        cur = conn.cursor()
        cur.execute("SELECT * FROM organizations WHERE owner_id = %s", (owner_id,))
        row = cur.fetchone()
        return dict(zip([d[0] for d in cur.description], row)) if row else None

def org_get_all() -> list:
    with get_db() as conn:
        if not conn:
            return list(_mem.get('orgs', {}).values())
        cur = conn.cursor()
        cur.execute("SELECT * FROM organizations ORDER BY created_at DESC")
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

def org_get_employees(org_id: str) -> list:
    with get_db() as conn:
        if not conn:
            return [u for u in _mem.get('users', {}).values() if u.get('org_id') == org_id]
        cur = conn.cursor()
        cur.execute("""
            SELECT id, name, email, role, status, last_login, created_at, avatar
            FROM users WHERE org_id = %s ORDER BY created_at DESC
        """, (org_id,))
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

def org_get_devices(org_id: str) -> list:
    with get_db() as conn:
        if not conn:
            return [d for d in _mem.get('org_devices_v2', {}).values() if d.get('org_id') == org_id]
        cur = conn.cursor()
        cur.execute("""
            SELECT d.*, u.name as user_name, u.email as user_email
            FROM org_devices_v2 d
            LEFT JOIN users u ON d.user_id = u.id
            WHERE d.org_id = %s ORDER BY d.last_seen DESC NULLS LAST
        """, (org_id,))
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

def invite_create(org_id: str, invited_by: str, email: str, name: str, role: str = 'employee') -> dict:
    import secrets
    token = secrets.token_urlsafe(32)
    with get_db() as conn:
        if not conn:
            inv = {'id': token[:8], 'org_id': org_id, 'email': email,
                   'name': name, 'role': role, 'token': token, 'status': 'pending'}
            _mem.setdefault('invites', {})[token] = inv
            return inv
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO invites (org_id, invited_by, email, name, role, token)
            VALUES (%s, %s, %s, %s, %s, %s) RETURNING *
        """, (org_id, invited_by, email, name, role, token))
        return dict(zip([d[0] for d in cur.description], cur.fetchone()))

def invite_get(token: str) -> dict:
    with get_db() as conn:
        if not conn:
            return _mem.get('invites', {}).get(token)
        cur = conn.cursor()
        cur.execute("SELECT * FROM invites WHERE token = %s AND status = 'pending' AND expires_at > NOW()", (token,))
        row = cur.fetchone()
        return dict(zip([d[0] for d in cur.description], row)) if row else None

def invite_accept(token: str) -> bool:
    with get_db() as conn:
        if not conn:
            if token in _mem.get('invites', {}):
                _mem['invites'][token]['status'] = 'accepted'
                return True
            return False
        cur = conn.cursor()
        cur.execute("UPDATE invites SET status = 'accepted' WHERE token = %s", (token,))
        return cur.rowcount > 0

def refresh_token_create(user_id: str) -> str:
    import secrets
    token = secrets.token_urlsafe(48)
    with get_db() as conn:
        if not conn:
            _mem.setdefault('refresh_tokens', {})[token] = {'user_id': user_id, 'token': token}
            return token
        cur = conn.cursor()
        cur.execute("INSERT INTO refresh_tokens (user_id, token) VALUES (%s, %s)", (user_id, token))
        return token

def refresh_token_verify(token: str) -> str:
    """Returns user_id if valid, None if expired/invalid"""
    with get_db() as conn:
        if not conn:
            rt = _mem.get('refresh_tokens', {}).get(token)
            return rt['user_id'] if rt else None
        cur = conn.cursor()
        cur.execute("SELECT user_id FROM refresh_tokens WHERE token = %s AND expires_at > NOW()", (token,))
        row = cur.fetchone()
        return row[0] if row else None

def org_device_register(org_id: str, user_id: str, hostname: str,
                         device_name: str, device_type: str, os_name: str,
                         ip: str = None, mac: str = None) -> dict:
    with get_db() as conn:
        if not conn:
            dev = {
                'id': 'dev-' + user_id[:8], 'org_id': org_id, 'user_id': user_id,
                'hostname': hostname, 'device_name': device_name,
                'device_type': device_type, 'os': os_name, 'ip_address': ip,
                'mac_address': mac, 'agent_token': 'at-' + user_id[:16],
                'last_score': 0, 'status': 'active', 'last_seen': None
            }
            _mem.setdefault('org_devices_v2', {})[dev['id']] = dev
            return dev
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO org_devices_v2 (org_id, user_id, hostname, device_name, device_type, os, ip_address, mac_address)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING *
        """, (org_id, user_id, hostname, device_name, device_type, os_name, ip, mac))
        return dict(zip([d[0] for d in cur.description], cur.fetchone()))

def org_device_heartbeat(agent_token: str, score: int = None, ip: str = None) -> bool:
    with get_db() as conn:
        if not conn:
            for dev in _mem.get('org_devices_v2', {}).values():
                if dev.get('agent_token') == agent_token:
                    dev['last_seen'] = 'now'
                    if score is not None: dev['last_score'] = score
                    return True
            return False
        cur = conn.cursor()
        cur.execute("""
            UPDATE org_devices_v2
            SET last_seen = NOW(),
                last_score = COALESCE(%s, last_score),
                ip_address  = COALESCE(%s, ip_address)
            WHERE agent_token = %s
        """, (score, ip, agent_token))
        return cur.rowcount > 0
