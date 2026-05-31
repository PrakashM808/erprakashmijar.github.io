/* auth.js — PM::OFFSEC authentication system v3
   Features: register, login, logout, forgot password,
             change password, admin user management */

const AUTH = (() => {
  const USERS_KEY   = 'pm_users_v2';
  const SESSION_KEY = 'pm_session_v2';
  const RESET_KEY   = 'pm_reset_tokens';

  /* ── Backend bridge ───────────────────────────────────────────
     Real accounts live in the backend (Postgres + JWT). These helpers
     let register/login use the backend as the source of truth when it
     is reachable, so accounts persist server-side and work across
     devices. If the backend is offline, we fall back to the local
     (per-browser) store so the app still works for demos/offline. */
  function backendUrl() {
    try {
      var s = JSON.parse(localStorage.getItem('pm_settings_v3') || 'null');
      if (s && s.apiUrl) return s.apiUrl.replace(/\/$/, '');
    } catch (e) {}
    var local = location.hostname === 'localhost' || location.hostname === '127.0.0.1';
    return local ? 'http://localhost:8000'
                 : (localStorage.getItem('pm_railway_url') || 'https://pm-offsec-backend-production.up.railway.app');
  }
  async function backendCall(path, body) {
    var ctrl = new AbortController();
    var timer = setTimeout(function(){ ctrl.abort(); }, 8000);
    try {
      var r = await fetch(backendUrl() + path, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal: ctrl.signal
      });
      clearTimeout(timer);
      var data = {};
      try { data = await r.json(); } catch (e) {}
      return { status: r.status, ok: r.ok, data: data };
    } catch (e) {
      clearTimeout(timer);
      return { status: 0, ok: false, offline: true, data: {} };
    }
  }
  // Build a UI session object from a backend auth response.
  function sessionFromBackend(resp, fallbackName) {
    var u = {
      id:    resp.user_id || ('user-' + Date.now()),
      name:  resp.name || fallbackName || (resp.email || '').split('@')[0],
      email: (resp.email || '').toLowerCase(),
      role:  resp.role || 'user',
      plan:  resp.plan || 'free',
      client_type: resp.client_type || 'individual',
      org_id: resp.org_id || resp.user_id,
      avatar:(resp.name || fallbackName || 'U').trim().split(' ').map(function(n){return n[0];}).join('').toUpperCase().slice(0,2),
      status:'active'
    };
    if (resp.access_token) localStorage.setItem('pm_jwt_token', resp.access_token);
    return u;
  }


  /* ── Default built-in accounts ──────────────────────────── */
  const DEFAULTS = [
    // ── YOUR REAL ADMIN ACCOUNT ──────────────────────────────────
    // IMPORTANT: Change the password below to your own strong password
    // before deploying. This is the only admin account.
    {
      id: 'admin-1', name: 'Prakash Mijar',
      email: 'admin@erprakashmijar.com',
      password: 'Admin@2026',  // ⚠️ CHANGE THIS PASSWORD BEFORE GO-LIVE
      role: 'admin', avatar: 'PM', created: '2026-05-28',
      phone: '+977', company: 'PM::OFFSEC',
      plan: 'enterprise', status: 'active',
      lastLogin: null, loginCount: 0,
      notes: 'Platform owner — full admin access'
    },
    // ── DEMO CLIENT (for showing clients how the portal looks) ───
    {
      id: 'demo-client-1', name: 'Demo Client',
      email: 'client@demo.com', password: 'Client@Demo1',
      role: 'client', avatar: 'DC', created: '2026-05-28',
      phone: '', company: 'Demo Corporation',
      plan: 'starter', status: 'active',
      lastLogin: null, loginCount: 0,
      notes: 'Demo account — safe to share with prospects'
    },
  ];

  /* ── Core storage ────────────────────────────────────────── */
  function getUsers() {
    try { return JSON.parse(localStorage.getItem(USERS_KEY)) || DEFAULTS; }
    catch { return DEFAULTS; }
  }
  function saveUsers(u) { localStorage.setItem(USERS_KEY, JSON.stringify(u)); }
  function getSession() {
    try {
      // sessionStorage is tab-isolated — fixes multi-account bug
      var s = sessionStorage.getItem(SESSION_KEY);
      if (s) return JSON.parse(s);
      // Fallback: check localStorage for "remember me" sessions
      var ls = localStorage.getItem(SESSION_KEY + '_persist');
      if (ls) return JSON.parse(ls);
      return null;
    } catch(e) { return null; }
  }
  function setSession(user, persist) {
    const s = { ...user, loginAt: Date.now() };
    delete s.password;
    // Always store in sessionStorage (tab-isolated) — prevents cross-tab session bleed
    sessionStorage.setItem(SESSION_KEY, JSON.stringify(s));
    // Also persist in localStorage if "remember me" or admin session
    if (persist || user.role === 'admin') {
      localStorage.setItem(SESSION_KEY + '_persist', JSON.stringify(s));
    }
    return s;
  }
  function clearSession() {
    sessionStorage.removeItem(SESSION_KEY);
    localStorage.removeItem(SESSION_KEY + '_persist');
    localStorage.removeItem(SESSION_KEY); // clean up old key too
    localStorage.removeItem('pm_jwt_token'); // clear backend token on logout
  }

  /* Init defaults on first visit */
  if (!localStorage.getItem(USERS_KEY)) saveUsers(DEFAULTS);


  /* ── 2FA Storage keys ───────────────────────────────────── */
  const MFA_KEY        = 'pm_mfa_v1';        // all mfa settings
  const MFA_SESSION    = 'pm_mfa_session';   // verified 2fa session

  /* ── TOTP helpers (RFC 6238 — works with Google Authenticator) ── */
  function _base32Decode(s) {
    var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    s = s.toUpperCase().replace(/=+$/, '');
    var bits = 0, val = 0, out = [];
    for (var i = 0; i < s.length; i++) {
      val = (val << 5) | chars.indexOf(s[i]);
      bits += 5;
      if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; }
    }
    return new Uint8Array(out);
  }

  async function _hmacSHA1(key, data) {
    var k = await crypto.subtle.importKey('raw', key, { name:'HMAC', hash:'SHA-1' }, false, ['sign']);
    var sig = await crypto.subtle.sign('HMAC', k, data);
    return new Uint8Array(sig);
  }

  async function generateTOTP(secret, timeStep) {
    var t = Math.floor((timeStep || Date.now() / 1000) / 30);
    var buf = new ArrayBuffer(8);
    var view = new DataView(buf);
    view.setUint32(4, t, false);
    var key = _base32Decode(secret);
    var hash = await _hmacSHA1(key, new Uint8Array(buf));
    var offset = hash[hash.length - 1] & 0xf;
    var code = ((hash[offset] & 0x7f) << 24)
             | ((hash[offset+1] & 0xff) << 16)
             | ((hash[offset+2] & 0xff) << 8)
             | (hash[offset+3] & 0xff);
    return String(code % 1000000).padStart(6, '0');
  }

  async function verifyTOTP(secret, token) {
    // Check current + 1 window before/after for clock drift
    var now = Math.floor(Date.now() / 1000);
    for (var delta = -1; delta <= 1; delta++) {
      var expected = await generateTOTP(secret, now + delta * 30);
      if (expected === String(token).trim()) return true;
    }
    return false;
  }

  function generateSecret() {
    var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    var secret = '';
    var arr = new Uint8Array(20);
    crypto.getRandomValues(arr);
    for (var i = 0; i < 20; i++) {
      secret += chars[arr[i] % 32];
    }
    return secret;
  }

  function getTotpUri(secret, email) {
    return 'otpauth://totp/PM%3A%3AOFFSEC%3A' + encodeURIComponent(email)
      + '?secret=' + secret
      + '&issuer=PM%3A%3AOFFSEC&algorithm=SHA1&digits=6&period=30';
  }

  /* ── MFA Settings ─────────────────────────────────────────── */
  function getMfaSettings(userId) {
    try {
      var all = JSON.parse(localStorage.getItem(MFA_KEY) || '{}');
      return all[userId] || { enabled: false, type: null, secret: null, backupCodes: [] };
    } catch(e) { return { enabled: false }; }
  }

  function saveMfaSettings(userId, settings) {
    try {
      var all = JSON.parse(localStorage.getItem(MFA_KEY) || '{}');
      all[userId] = { ...all[userId], ...settings };
      localStorage.setItem(MFA_KEY, JSON.stringify(all));
    } catch(e) {}
  }

  function generateBackupCodes() {
    var codes = [];
    for (var i = 0; i < 10; i++) {
      var arr = new Uint8Array(4);
      crypto.getRandomValues(arr);
      var hex = Array.from(arr).map(function(b){ return b.toString(16).padStart(2,'0'); }).join('');
      codes.push(hex.substr(0,4) + '-' + hex.substr(4,4));
    }
    return codes;
  }

  function useBackupCode(userId, code) {
    var mfa = getMfaSettings(userId);
    var codes = mfa.backupCodes || [];
    var idx = codes.indexOf(code.trim().toLowerCase());
    if (idx === -1) return false;
    codes.splice(idx, 1);  // each backup code can only be used once
    saveMfaSettings(userId, { backupCodes: codes });
    return true;
  }

  /* ── Email OTP (for 2FA fallback) ─────────────────────────── */
  var _emailOtpStore = {};  // in-memory: { userId: { otp, expires, email } }

  function generateEmailOtp(userId, email) {
    var otp = String(Math.floor(100000 + Math.random() * 900000));
    _emailOtpStore[userId] = {
      otp: otp,
      expires: Date.now() + 5 * 60 * 1000,  // 5 minutes
      email: email
    };
    return otp;
  }

  function verifyEmailOtp(userId, code) {
    var entry = _emailOtpStore[userId];
    if (!entry) return false;
    if (Date.now() > entry.expires) { delete _emailOtpStore[userId]; return false; }
    if (entry.otp !== String(code).trim()) return false;
    delete _emailOtpStore[userId];
    return true;
  }

  /* ── 2FA Session tracking ──────────────────────────────────── */
  function setMfaVerified(userId) {
    var data = {};
    try { data = JSON.parse(sessionStorage.getItem(MFA_SESSION) || '{}'); } catch(e){}
    data[userId] = { verified: true, at: Date.now(), expires: Date.now() + 12 * 60 * 60 * 1000 };
    sessionStorage.setItem(MFA_SESSION, JSON.stringify(data));
  }

  function isMfaVerified(userId) {
    try {
      var data = JSON.parse(sessionStorage.getItem(MFA_SESSION) || '{}');
      var entry = data[userId];
      if (!entry || !entry.verified) return false;
      if (Date.now() > entry.expires) return false;  // 12-hour session
      return true;
    } catch(e) { return false; }
  }

  function clearMfaSession(userId) {
    try {
      var data = JSON.parse(localStorage.getItem(MFA_SESSION) || '{}');
      delete data[userId];
      sessionStorage.setItem(MFA_SESSION, JSON.stringify(data));
    } catch(e) {}
  }

  /* ── Setup 2FA (returns secret + QR data) ─────────────────── */
  async function setup2FA(userId, email, type) {
    if (type === 'totp') {
      var secret = generateSecret();
      var uri = getTotpUri(secret, email);
      var backupCodes = generateBackupCodes();
      // Save pending (not enabled until verified)
      saveMfaSettings(userId, {
        pending_secret: secret,
        pending_type: 'totp',
        backupCodes: backupCodes
      });
      return { ok: true, secret: secret, uri: uri, backupCodes: backupCodes };
    }
    if (type === 'email') {
      saveMfaSettings(userId, { pending_type: 'email' });
      return { ok: true, type: 'email' };
    }
    return { ok: false, error: 'Unknown 2FA type' };
  }

  /* ── Verify setup token and enable 2FA ────────────────────── */
  async function enable2FA(userId, token) {
    var mfa = getMfaSettings(userId);
    if (!mfa.pending_secret && mfa.pending_type !== 'email') {
      return { ok: false, error: '2FA setup not initiated' };
    }
    if (mfa.pending_type === 'totp') {
      var valid = await verifyTOTP(mfa.pending_secret, token);
      if (!valid) return { ok: false, error: 'Invalid code. Make sure your authenticator app time is correct.' };
      saveMfaSettings(userId, {
        enabled: true, type: 'totp',
        secret: mfa.pending_secret,
        pending_secret: null, pending_type: null,
        enabledAt: new Date().toISOString()
      });
      setMfaVerified(userId);
      return { ok: true };
    }
    if (mfa.pending_type === 'email') {
      saveMfaSettings(userId, {
        enabled: true, type: 'email',
        pending_type: null,
        enabledAt: new Date().toISOString()
      });
      setMfaVerified(userId);
      return { ok: true };
    }
    return { ok: false, error: 'Unknown error' };
  }

  /* ── Verify 2FA during login ───────────────────────────────── */
  async function verify2FA(userId, token) {
    var mfa = getMfaSettings(userId);
    if (!mfa.enabled) return { ok: true };  // 2FA not enabled — pass through

    // Check backup codes first
    if (token.includes('-') && useBackupCode(userId, token)) {
      setMfaVerified(userId);
      return { ok: true, usedBackup: true };
    }

    if (mfa.type === 'totp') {
      var valid = await verifyTOTP(mfa.secret, token);
      if (valid) { setMfaVerified(userId); return { ok: true }; }
      return { ok: false, error: 'Invalid authenticator code. Try again.' };
    }
    if (mfa.type === 'email') {
      var emailValid = verifyEmailOtp(userId, token);
      if (emailValid) { setMfaVerified(userId); return { ok: true }; }
      return { ok: false, error: 'Invalid or expired email code.' };
    }
    return { ok: false, error: 'Unknown 2FA type' };
  }

  /* ── Disable 2FA ───────────────────────────────────────────── */
  function disable2FA(userId, password) {
    var users = getUsers();
    var user = users.find(function(u){ return u.id === userId; });
    if (!user || user.password !== password) {
      return { ok: false, error: 'Incorrect password.' };
    }
    saveMfaSettings(userId, {
      enabled: false, type: null, secret: null,
      backupCodes: [], pending_secret: null
    });
    clearMfaSession(userId);
    return { ok: true };
  }



  /* ── Login ───────────────────────────────────────────────── */
  function login(email, password) {
    const users = getUsers();
    const user  = users.find(u =>
      u.email.toLowerCase() === email.toLowerCase() && u.password === password
    );
    if (!user)
      return { ok: false, error: 'Invalid email or password. Check your credentials and try again.' };
    if (user.status === 'suspended')
      return { ok: false, error: 'This account has been suspended. Contact admin@erprakashmijar.com.' };

    // ── 2FA CHECK ──────────────────────────────────────────────
    const mfa = getMfaSettings(user.id);
    if (mfa.enabled && !isMfaVerified(user.id)) {
      // Store pending login — need 2FA verification before creating session
      localStorage.setItem('pm_2fa_pending', JSON.stringify({
        userId: user.id, email: user.email, name: user.name,
        expires: Date.now() + 5 * 60 * 1000
      }));
      return { ok: false, requires2FA: true, mfaType: mfa.type, userId: user.id };
    }

    // Update last login
    const idx = users.findIndex(u => u.id === user.id);
    users[idx].lastLogin  = new Date().toISOString();
    users[idx].loginCount = (users[idx].loginCount || 0) + 1;
    saveUsers(users);
    return { ok: true, session: setSession(users[idx]) };
  }

  function completeLoginAfter2FA(userId) {
    var pending = null;
    try { pending = JSON.parse(localStorage.getItem('pm_2fa_pending')); } catch(e){}
    if (!pending || pending.userId !== userId)
      return { ok: false, error: 'Session expired. Please log in again.' };
    if (Date.now() > pending.expires) {
      localStorage.removeItem('pm_2fa_pending');
      return { ok: false, error: '2FA window expired. Please log in again.' };
    }
    const users = getUsers();
    const user = users.find(function(u){ return u.id === userId; });
    if (!user) return { ok: false, error: 'User not found.' };
    localStorage.removeItem('pm_2fa_pending');
    const idx = users.findIndex(function(u){ return u.id === userId; });
    users[idx].lastLogin = new Date().toISOString();
    users[idx].loginCount = (users[idx].loginCount || 0) + 1;
    saveUsers(users);
    return { ok: true, session: setSession(users[idx]) };
  }

  /* ── Register ────────────────────────────────────────────── */
  function register(name, email, password, clientType) {
    if (!name || name.trim().length < 2)
      return { ok: false, error: 'Name must be at least 2 characters.' };
    if (!email || !email.includes('@'))
      return { ok: false, error: 'Please enter a valid email address.' };
    if (!password || password.length < 8)
      return { ok: false, error: 'Password must be at least 8 characters.' };
    if (!/[A-Z]/.test(password))
      return { ok: false, error: 'Password must contain at least one uppercase letter.' };
    if (!/[0-9]/.test(password))
      return { ok: false, error: 'Password must contain at least one number.' };
    const users = getUsers();
    if (users.find(u => u.email.toLowerCase() === email.toLowerCase()))
      return { ok: false, error: 'An account with this email already exists. Try logging in.' };
    const uid = 'user-' + Date.now();
    const newUser = {
      id:         uid,
      name:       name.trim(),
      email:      email.toLowerCase(),
      password,
      role:       'user',
      client_type:(clientType === 'business') ? 'business' : 'individual',
      org_id:     uid,
      avatar:     name.trim().split(' ').map(n => n[0]).join('').toUpperCase().slice(0, 2),
      created:    new Date().toISOString().split('T')[0],
      phone:      '',
      company:    '',
      plan:       'free',
      status:     'active',
      lastLogin:  null,
      loginCount: 0,
      notes:      ''
    };
    users.push(newUser);
    saveUsers(users);
    return { ok: true, session: setSession(newUser) };
  }

  /* ── Backend-first register (real server account when online) ── */
  async function registerBackend(name, email, password, clientType) {
    if (!name || name.trim().length < 2) return { ok:false, error:'Name must be at least 2 characters.' };
    if (!email || !email.includes('@')) return { ok:false, error:'Please enter a valid email address.' };
    if (!password || password.length < 8) return { ok:false, error:'Password must be at least 8 characters.' };
    if (!/[A-Z]/.test(password)) return { ok:false, error:'Password must contain at least one uppercase letter.' };
    if (!/[0-9]/.test(password)) return { ok:false, error:'Password must contain at least one number.' };

    var ctype = (clientType === 'business') ? 'business' : 'individual';
    var resp = await backendCall('/api/auth/register', { email: email.toLowerCase(), password: password, name: name.trim(), plan: 'free', client_type: ctype });
    if (resp.offline) {
      var r = register(name, email, password, ctype);   // backend down → local fallback
      if (r.ok) r.local_only = true;
      return r;
    }
    if (resp.ok && resp.data && resp.data.access_token) {
      try {
        var users = getUsers();
        if (!users.find(function(u){ return u.email.toLowerCase() === email.toLowerCase(); })) {
          register(name, email, password);        // mirror locally for admin/offline
        }
      } catch (e) {}
      return { ok: true, session: setSession(sessionFromBackend(resp.data, name)) };
    }
    var msg = (resp.data && (resp.data.detail || resp.data.error)) || 'This email may already be registered — try logging in.';
    return { ok: false, error: typeof msg === 'string' ? msg : 'Registration failed.' };
  }

  /* ── Backend-first login (authenticate against server when online) ── */
  async function loginBackend(email, password) {
    var resp = await backendCall('/api/auth/login', { email: (email||'').toLowerCase(), password: password });
    if (resp.offline) return login(email, password);   // backend down → local check
    if (resp.ok && resp.data && resp.data.access_token) {
      try {
        var users = getUsers();
        var lu = users.find(function(u){ return u.email.toLowerCase() === (email||'').toLowerCase(); });
        if (lu) {
          var mfa = getMfaSettings(lu.id);
          if (mfa.enabled && !isMfaVerified(lu.id)) {
            localStorage.setItem('pm_2fa_pending', JSON.stringify({ userId: lu.id, email: lu.email, name: lu.name, expires: Date.now() + 5*60*1000 }));
            localStorage.setItem('pm_jwt_token', resp.data.access_token);
            return { ok: false, requires2FA: true, mfaType: mfa.type, userId: lu.id };
          }
        }
      } catch (e) {}
      return { ok: true, session: setSession(sessionFromBackend(resp.data)) };
    }
    // Backend reachable but rejected the credentials. The account may exist only
    // locally (e.g. the built-in demo accounts that aren't in the server DB yet),
    // so try a local login before failing. Real server accounts still win above.
    var localTry = login(email, password);
    if (localTry && localTry.ok) return localTry;
    if (localTry && localTry.requires2FA) return localTry;
    var msg = (resp.data && (resp.data.detail || resp.data.error)) || 'Invalid email or password.';
    return { ok: false, error: typeof msg === 'string' ? msg : 'Invalid email or password.' };
  }

  /* ── Logout ──────────────────────────────────────────────── */
  function logout(redirect = '../login.html') {
    clearSession();
    // Clear shared portal session
    try { localStorage.removeItem('pm_portal_session'); localStorage.removeItem('pm_portal_jwt'); localStorage.removeItem('pm_biz_jwt'); localStorage.removeItem('pm_admin_jwt'); } catch(e) {}
    window.location.href = redirect;
  }

  /* ── Guards ──────────────────────────────────────────────── */
  function requireAuth(redirectTo = '../login.html') {
    const s = getSession();
    if (!s) { window.location.href = redirectTo; return null; }
    // Enforce 24-hour session expiry
    const SESSION_MAX_AGE_MS = 24 * 60 * 60 * 1000;
    if (s.loginAt && (Date.now() - s.loginAt) > SESSION_MAX_AGE_MS) {
      sessionStorage.removeItem('pm_session_v2');
      localStorage.removeItem('pm_session_v2');
      window.location.href = redirectTo;
      return null;
    }
    return s;
  }
  function requireGuest(redirectTo = 'dashboard/index.html') {
    const s = getSession();
    if (s) { window.location.href = redirectTo; return null; }
    return true;
  }

  /* ── Forgot password — generates a reset token ───────────── */
  function forgotPassword(email) {
    const users = getUsers();
    const user  = users.find(u => u.email.toLowerCase() === email.toLowerCase());
    if (!user)
      return { ok: false, error: 'No account found with that email address.' };

    // Generate 6-digit OTP + token
    const otp   = Math.floor(100000 + Math.random() * 900000).toString();
    const token = 'rst-' + Date.now() + '-' + Math.random().toString(36).slice(2);
    const expires = Date.now() + 15 * 60 * 1000; // 15 minutes

    const tokens = JSON.parse(localStorage.getItem(RESET_KEY) || '{}');
    tokens[token] = { userId: user.id, email: user.email, otp, expires };
    localStorage.setItem(RESET_KEY, JSON.stringify(tokens));

    // In a real app this would email the OTP. Here we surface it clearly.
    return { ok: true, token, otp, email: user.email, name: user.name,
             note: 'In production, this OTP would be emailed. For demo, it is shown on screen.' };
  }

  /* ── Verify OTP ──────────────────────────────────────────── */
  function verifyOTP(token, otp) {
    const tokens = JSON.parse(localStorage.getItem(RESET_KEY) || '{}');
    const entry  = tokens[token];
    if (!entry)              return { ok: false, error: 'Invalid or expired reset link.' };
    if (Date.now() > entry.expires) return { ok: false, error: 'This OTP has expired. Please request a new one.' };
    if (entry.otp !== otp.trim()) return { ok: false, error: 'Incorrect OTP. Check and try again.' };
    return { ok: true, token, userId: entry.userId, email: entry.email };
  }

  /* ── Reset password (after OTP verified) ─────────────────── */
  function resetPassword(token, otp, newPassword) {
    const verify = verifyOTP(token, otp);
    if (!verify.ok) return verify;

    const strength = passwordStrength(newPassword);
    if (!newPassword || newPassword.length < 8)
      return { ok: false, error: 'Password must be at least 8 characters.' };
    if (!/[A-Z]/.test(newPassword))
      return { ok: false, error: 'Password must contain at least one uppercase letter.' };
    if (!/[0-9]/.test(newPassword))
      return { ok: false, error: 'Password must contain at least one number.' };

    const users = getUsers();
    const idx   = users.findIndex(u => u.id === verify.userId);
    if (idx === -1) return { ok: false, error: 'User account not found.' };

    users[idx].password = newPassword;
    saveUsers(users);

    // Invalidate token
    const tokens = JSON.parse(localStorage.getItem(RESET_KEY) || '{}');
    delete tokens[token];
    localStorage.setItem(RESET_KEY, JSON.stringify(tokens));

    return { ok: true, message: 'Password reset successfully. You can now log in.' };
  }

  /* ── Change password (logged-in user) ────────────────────── */
  function changePassword(userId, currentPassword, newPassword) {
    const users = getUsers();
    const idx   = users.findIndex(u => u.id === userId);
    if (idx === -1) return { ok: false, error: 'User not found.' };
    if (users[idx].password !== currentPassword)
      return { ok: false, error: 'Current password is incorrect.' };
    if (!newPassword || newPassword.length < 8)
      return { ok: false, error: 'New password must be at least 8 characters.' };
    if (!/[A-Z]/.test(newPassword))
      return { ok: false, error: 'New password must contain at least one uppercase letter.' };
    if (!/[0-9]/.test(newPassword))
      return { ok: false, error: 'New password must contain at least one number.' };
    if (currentPassword === newPassword)
      return { ok: false, error: 'New password must be different from your current password.' };
    users[idx].password = newPassword;
    saveUsers(users);
    return { ok: true };
  }

  /* ── Admin: get ALL users with full data ─────────────────── */
  function getAllUsersAdmin() {
    return getUsers(); // includes password — admin only, never expose to non-admin UI
  }
  function getAllUsers() {
    return getUsers().map(u => { const { password, ...rest } = u; return rest; });
  }

  /* ── Admin: update a user ────────────────────────────────── */
  function adminUpdateUser(userId, updates, adminId) {
    const users = getUsers();
    const admin = users.find(u => u.id === adminId);
    if (!admin || admin.role !== 'admin')
      return { ok: false, error: 'Insufficient permissions.' };
    const idx = users.findIndex(u => u.id === userId);
    if (idx === -1) return { ok: false, error: 'User not found.' };

    const allowed = ['name','email','role','phone','company','plan','status','notes','avatar'];
    allowed.forEach(k => { if (updates[k] !== undefined) users[idx][k] = updates[k]; });

    // If password reset by admin
    if (updates.newPassword) {
      if (updates.newPassword.length < 8)
        return { ok: false, error: 'Password must be at least 8 characters.' };
      users[idx].password = updates.newPassword;
    }
    saveUsers(users);
    return { ok: true, user: users[idx] };
  }

  /* ── Admin: delete a user ────────────────────────────────── */
  function adminDeleteUser(userId, adminId) {
    const users = getUsers();
    const admin = users.find(u => u.id === adminId);
    if (!admin || admin.role !== 'admin')
      return { ok: false, error: 'Insufficient permissions.' };
    if (userId === adminId)
      return { ok: false, error: 'You cannot delete your own account.' };
    const filtered = users.filter(u => u.id !== userId);
    if (filtered.length === users.length)
      return { ok: false, error: 'User not found.' };
    saveUsers(filtered);
    return { ok: true };
  }

  /* ── Admin: create a user ────────────────────────────────── */
  function adminCreateUser(data, adminId) {
    const users = getUsers();
    const admin = users.find(u => u.id === adminId);
    if (!admin || admin.role !== 'admin')
      return { ok: false, error: 'Insufficient permissions.' };
    if (!data.email || !data.name || !data.password)
      return { ok: false, error: 'Name, email, and password are required.' };
    if (users.find(u => u.email.toLowerCase() === data.email.toLowerCase()))
      return { ok: false, error: 'An account with this email already exists.' };
    const newUser = {
      id: 'user-' + Date.now(),
      name: data.name.trim(),
      email: data.email.toLowerCase(),
      password: data.password,
      role: data.role || 'user',
      avatar: data.name.trim().split(' ').map(n => n[0]).join('').toUpperCase().slice(0, 2),
      created: new Date().toISOString().split('T')[0],
      phone: data.phone || '',
      company: data.company || '',
      plan: data.plan || 'free',
      status: 'active',
      lastLogin: null,
      loginCount: 0,
      notes: data.notes || ''
    };
    users.push(newUser);
    saveUsers(users);
    return { ok: true, user: newUser };
  }

  /* ── Password strength ───────────────────────────────────── */
  function passwordStrength(pw) {
    if (!pw) return { score: 0, label: '', color: '' };
    let score = 0;
    if (pw.length >= 8)              score++;
    if (pw.length >= 12)             score++;
    if (/[A-Z]/.test(pw))            score++;
    if (/[0-9]/.test(pw))            score++;
    if (/[^A-Za-z0-9]/.test(pw))     score++;
    const map = [
      { label: '',        color: '' },
      { label: 'WEAK',    color: '#ff3b5c' },
      { label: 'FAIR',    color: '#f59e0b' },
      { label: 'GOOD',    color: '#00d4ff' },
      { label: 'STRONG',  color: '#00ff88' },
      { label: 'PERFECT', color: '#00ff88' },
    ];
    return { score, ...map[Math.min(score, 5)] };
  }


  /* ── OAuth login/register ─────────────────────────────────── */
  function loginWithOAuth(email, provider, providerId) {
    var users = getUsers();
    var user = users.find(function(u){ return u.email.toLowerCase() === email.toLowerCase(); });
    if (!user) return { ok: false, error: 'No account with this ' + provider + ' email. Please register.' };
    if (user.status === 'suspended') return { ok: false, error: 'Account suspended.' };
    var idx = users.findIndex(function(u){ return u.id === user.id; });
    users[idx].lastLogin = new Date().toISOString();
    users[idx].loginCount = (users[idx].loginCount||0) + 1;
    users[idx].oauthProvider = provider;
    saveUsers(users);
    return { ok: true, session: setSession(users[idx]) };
  }

  function registerWithOAuth(email, name, provider, providerId, plan) {
    plan = plan || 'free';
    var users = getUsers();
    if (users.find(function(u){ return u.email.toLowerCase() === email.toLowerCase(); })) {
      return loginWithOAuth(email, provider, providerId);
    }
    var userId = 'u' + Date.now().toString(36);
    var nameParts = (name||'').split(' ');
    var newUser = {
      id: userId, email: email.toLowerCase(),
      name: name || email.split('@')[0],
      password: 'oauth_' + provider + '_' + providerId,
      role: 'user', plan: plan, status: 'active',
      oauthProvider: provider, oauthId: providerId,
      created: new Date().toISOString(), loginCount: 1,
      lastLogin: new Date().toISOString()
    };
    users.push(newUser);
    saveUsers(users);
    return { ok: true, session: setSession(newUser) };
  }


  return {
    login, register, logout,
    loginBackend, registerBackend,
    requireAuth, requireGuest, getSession,

    forgotPassword, verifyOTP, resetPassword, changePassword,
    getAllUsers, getAllUsersAdmin,
    adminUpdateUser, adminDeleteUser, adminCreateUser,
    passwordStrength, getUsers, saveUsers,

    // 2FA / MFA
    getMfaSettings, saveMfaSettings, generateBackupCodes,
    setup2FA, enable2FA, verify2FA, disable2FA,
    setMfaVerified, isMfaVerified, completeLoginAfter2FA
  };
})();

/* ── Canvas particles ──────────────────────────────────────── */
function initCanvas(canvasId) {
  const c = document.getElementById(canvasId);
  if (!c) return;
  const ctx = c.getContext('2d');
  let W, H, pts = [];
  const resize = () => { W = c.width = window.innerWidth; H = c.height = window.innerHeight; init(); };
  const init   = () => {
    pts = [];
    const n = Math.min(Math.floor((W * H) / 22000), 60);
    for (let i = 0; i < n; i++)
      pts.push({ x: Math.random()*W, y: Math.random()*H,
                 vx: (Math.random()-.5)*.2, vy: (Math.random()-.5)*.2,
                 r: Math.random()*1.2+.3 });
  };
  const draw = () => {
    ctx.clearRect(0, 0, W, H);
    pts.forEach(p => {
      p.x += p.vx; p.y += p.vy;
      if (p.x < 0) p.x = W; if (p.x > W) p.x = 0;
      if (p.y < 0) p.y = H; if (p.y > H) p.y = 0;
      ctx.beginPath(); ctx.arc(p.x, p.y, p.r, 0, Math.PI*2);
      ctx.fillStyle = 'rgba(0,255,136,0.4)'; ctx.fill();
    });
    for (let i = 0; i < pts.length; i++)
      for (let j = i+1; j < pts.length; j++) {
        const a = pts[i], b = pts[j], dx = a.x-b.x, dy = a.y-b.y;
        const d = Math.sqrt(dx*dx + dy*dy);
        if (d < 100) {
          ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y);
          ctx.strokeStyle = `rgba(0,255,136,${.06*(1-d/100)})`;
          ctx.lineWidth = .5; ctx.stroke();
        }
      }
    requestAnimationFrame(draw);
  };
  window.addEventListener('resize', resize);
  resize(); draw();
}

/* ── Custom cursor ─────────────────────────────────────────── */
function initCursor() {
  if (!window.matchMedia('(hover:hover) and (pointer:fine)').matches) return;
  const c = document.getElementById('cur'), r = document.getElementById('cur2');
  if (!c || !r) return;
  let mx = 0, my = 0, rx = 0, ry = 0;
  document.addEventListener('mousemove', e => {
    mx = e.clientX; my = e.clientY;
    c.style.left = mx+'px'; c.style.top = my+'px';
  });
  (function t() {
    rx += (mx-rx)*.11; ry += (my-ry)*.11;
    r.style.left = rx+'px'; r.style.top = ry+'px';
    requestAnimationFrame(t);
  })();
  document.addEventListener('mouseover', e => {
    const big = e.target.matches('a,button,input,select,.demo-role,[data-hover]');
    c.style.width  = big ? '18px' : '8px';
    c.style.height = big ? '18px' : '8px';
    r.style.width  = big ? '46px' : '30px';
    r.style.height = big ? '46px' : '30px';
  });
}
