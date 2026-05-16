/* auth.js — shared authentication system (localStorage-based) */

const AUTH = (() => {
  const USERS_KEY  = 'pm_users_v2';
  const SESSION_KEY = 'pm_session_v2';

  /* Default built-in accounts */
  const DEFAULTS = [
    { id: 'admin-1', name: 'Prakash Mijar', email: 'admin@erprakashmijar.com', password: 'Admin@2026', role: 'admin',  avatar: 'PM', created: '2026-01-01' },
    { id: 'client-1', name: 'Demo Client',  email: 'client@demo.com',          password: 'Client@123',  role: 'client', avatar: 'DC', created: '2026-01-01' },
  ];

  function getUsers() {
    try { return JSON.parse(localStorage.getItem(USERS_KEY)) || DEFAULTS; }
    catch { return DEFAULTS; }
  }
  function saveUsers(users) { localStorage.setItem(USERS_KEY, JSON.stringify(users)); }
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

  /* Init defaults if first visit */
  if (!localStorage.getItem(USERS_KEY)) saveUsers(DEFAULTS);

  function login(email, password) {
    const users = getUsers();
    const user = users.find(u => u.email.toLowerCase() === email.toLowerCase() && u.password === password);
    if (!user) return { ok: false, error: 'Invalid email or password. Check your credentials and try again.' };
    return { ok: true, session: setSession(user) };
  }

  function register(name, email, password) {
    if (!name || name.trim().length < 2)       return { ok: false, error: 'Name must be at least 2 characters.' };
    if (!email || !email.includes('@'))         return { ok: false, error: 'Please enter a valid email address.' };
    if (!password || password.length < 8)       return { ok: false, error: 'Password must be at least 8 characters.' };
    if (!/[A-Z]/.test(password))                return { ok: false, error: 'Password must contain at least one uppercase letter.' };
    if (!/[0-9]/.test(password))                return { ok: false, error: 'Password must contain at least one number.' };
    const users = getUsers();
    if (users.find(u => u.email.toLowerCase() === email.toLowerCase()))
      return { ok: false, error: 'An account with this email already exists. Try logging in.' };
    const newUser = {
      id: 'user-' + Date.now(),
      name: name.trim(),
      email: email.toLowerCase(),
      password,
      role: 'user',
      avatar: name.trim().split(' ').map(n => n[0]).join('').toUpperCase().slice(0, 2),
      created: new Date().toISOString().split('T')[0],
    };
    users.push(newUser);
    saveUsers(users);
    return { ok: true, session: setSession(newUser) };
  }

  function logout() {
    clearSession();
    window.location.href = '../login.html';
  }

  function requireAuth(redirectTo = '../login.html') {
    const session = getSession();
    if (!session) { window.location.href = redirectTo; return null; }
    return session;
  }

  function requireGuest(redirectTo = 'dashboard/index.html') {
    const session = getSession();
    if (session) { window.location.href = redirectTo; return null; }
    return true;
  }

  function getAllUsers() { return getUsers().map(u => { const {password, ...rest} = u; return rest; }); }

  function passwordStrength(pw) {
    if (!pw) return { score: 0, label: '', color: '' };
    let score = 0;
    if (pw.length >= 8)  score++;
    if (pw.length >= 12) score++;
    if (/[A-Z]/.test(pw)) score++;
    if (/[0-9]/.test(pw)) score++;
    if (/[^A-Za-z0-9]/.test(pw)) score++;
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

  return { login, register, logout, requireAuth, requireGuest, getSession, getAllUsers, passwordStrength, getUsers, saveUsers };
})();

/* Canvas particles (shared) */
function initCanvas(canvasId) {
  const c = document.getElementById(canvasId);
  if (!c) return;
  const ctx = c.getContext('2d');
  let W, H, pts = [];
  const resize = () => { W = c.width = window.innerWidth; H = c.height = window.innerHeight; init(); };
  const init = () => { pts = []; const n = Math.min(Math.floor((W*H)/22000), 60); for (let i=0;i<n;i++) pts.push({x:Math.random()*W,y:Math.random()*H,vx:(Math.random()-.5)*.2,vy:(Math.random()-.5)*.2,r:Math.random()*1.2+.3}); };
  const draw = () => {
    ctx.clearRect(0,0,W,H);
    pts.forEach(p => { p.x+=p.vx; p.y+=p.vy; if(p.x<0)p.x=W; if(p.x>W)p.x=0; if(p.y<0)p.y=H; if(p.y>H)p.y=0; ctx.beginPath(); ctx.arc(p.x,p.y,p.r,0,Math.PI*2); ctx.fillStyle='rgba(0,255,136,0.4)'; ctx.fill(); });
    for(let i=0;i<pts.length;i++) for(let j=i+1;j<pts.length;j++) { const a=pts[i],b=pts[j],dx=a.x-b.x,dy=a.y-b.y,d=Math.sqrt(dx*dx+dy*dy); if(d<100){ctx.beginPath();ctx.moveTo(a.x,a.y);ctx.lineTo(b.x,b.y);ctx.strokeStyle=`rgba(0,255,136,${.06*(1-d/100)})`;ctx.lineWidth=.5;ctx.stroke();} }
    requestAnimationFrame(draw);
  };
  window.addEventListener('resize', resize);
  resize(); draw();
}

/* Custom cursor (shared) */
function initCursor() {
  if (!window.matchMedia('(hover:hover) and (pointer:fine)').matches) return;
  const c = document.getElementById('cur'), r = document.getElementById('cur2');
  if (!c || !r) return;
  let mx=0,my=0,rx=0,ry=0;
  document.addEventListener('mousemove', e => { mx=e.clientX; my=e.clientY; c.style.left=mx+'px'; c.style.top=my+'px'; });
  (function t(){ rx+=(mx-rx)*.11; ry+=(my-ry)*.11; r.style.left=rx+'px'; r.style.top=ry+'px'; requestAnimationFrame(t); })();
  document.addEventListener('mouseover', e => {
    const big = e.target.matches('a,button,input,select,.demo-role,[data-hover]');
    c.style.width = big ? '18px' : '8px'; c.style.height = big ? '18px' : '8px';
    r.style.width = big ? '46px' : '30px'; r.style.height = big ? '46px' : '30px';
  });
}
