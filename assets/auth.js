/* auth.js — PM::OFFSEC authentication system v3
   Features: register, login, logout, forgot password,
             change password, admin user management */

const AUTH = (() => {
  const USERS_KEY   = 'pm_users_v2';
  const SESSION_KEY = 'pm_session_v2';
  const RESET_KEY   = 'pm_reset_tokens';

  /* ── Default built-in accounts ──────────────────────────── */
  const DEFAULTS = [
    {
      id: 'admin-1', name: 'Prakash Mijar',
      email: 'admin@erprakashmijar.com', password: 'Admin@2026',
      role: 'admin', avatar: 'PM', created: '2026-01-01',
      phone: '+1 (555) 000-0001', company: 'PM::OFFSEC',
      plan: 'enterprise'  /* admin always gets enterprise = unlimited */, status: 'active',
      lastLogin: null, loginCount: 0, notes: 'System admin account'
    },
    {
      id: 'client-1', name: 'Demo Client',
      email: 'client@demo.com', password: 'Client@123',
      role: 'client', avatar: 'DC', created: '2026-01-01',
      phone: '', company: 'Demo Corp',
      plan: 'starter', status: 'active',
      lastLogin: null, loginCount: 0, notes: 'Demo client account'
    },
  ];

  /* ── Core storage ────────────────────────────────────────── */
  function getUsers() {
    try { return JSON.parse(localStorage.getItem(USERS_KEY)) || DEFAULTS; }
    catch { return DEFAULTS; }
  }
  function saveUsers(u) { localStorage.setItem(USERS_KEY, JSON.stringify(u)); }
  function getSession() {
    try { return JSON.parse(localStorage.getItem(SESSION_KEY)); }
    catch { return null; }
  }
  function setSession(user) {
    const s = { ...user, loginAt: Date.now() };
    delete s.password;
    localStorage.setItem(SESSION_KEY, JSON.stringify(s));
    return s;
  }
  function clearSession() { localStorage.removeItem(SESSION_KEY); }

  /* Init defaults on first visit */
  if (!localStorage.getItem(USERS_KEY)) saveUsers(DEFAULTS);

  /* ── Login ───────────────────────────────────────────────── */
  function login(email, password) {
    const users = getUsers();
    const idx   = users.findIndex(u =>
      u.email.toLowerCase() === email.toLowerCase() && u.password === password
    );
    if (idx === -1)
      return { ok: false, error: 'Invalid email or password. Check your credentials and try again.' };
    if (users[idx].status === 'suspended')
      return { ok: false, error: 'This account has been suspended. Contact admin@erprakashmijar.com.' };
    // Update last login
    users[idx].lastLogin  = new Date().toISOString();
    users[idx].loginCount = (users[idx].loginCount || 0) + 1;
    saveUsers(users);
    return { ok: true, session: setSession(users[idx]) };
  }

  /* ── Register ────────────────────────────────────────────── */
  function register(name, email, password) {
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
    const newUser = {
      id:         'user-' + Date.now(),
      name:       name.trim(),
      email:      email.toLowerCase(),
      password,
      role:       'user',
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

  /* ── Logout ──────────────────────────────────────────────── */
  function logout(redirect = '../login.html') {
    clearSession();
    window.location.href = redirect;
  }

  /* ── Guards ──────────────────────────────────────────────── */
  function requireAuth(redirectTo = '../login.html') {
    const s = getSession();
    if (!s) { window.location.href = redirectTo; return null; }
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

  return {
    login, register, logout,
    requireAuth, requireGuest, getSession,
    forgotPassword, verifyOTP, resetPassword, changePassword,
    getAllUsers, getAllUsersAdmin,
    adminUpdateUser, adminDeleteUser, adminCreateUser,
    passwordStrength, getUsers, saveUsers
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
