// 00-sanitize.js — extracted from index.html
/* ═══════════════════════════════════════════════════════════════
   CORE UTILITY FUNCTIONS — showToast, scoreColor,
   modal open/close helpers, missing function stubs
   All 100+ showToast calls now have a real implementation
═══════════════════════════════════════════════════════════════ */

/* ── showToast — used 100+ times throughout dashboard ─────── */
function showToast(msg, type) {
  // type: 'ok' | 'warn' | 'danger' | 'info' | string color
  var colors = {
    ok:     {bg:'#22e3ff', text:'#040810'},
    warn:   {bg:'#f5a623', text:'#040810'},
    danger: {bg:'#ff4d6a', text:'#fff'},
    info:   {bg:'#4d8dff', text:'#040810'},
    error:  {bg:'#ff4d6a', text:'#fff'},
  };
  var col = colors[type] || colors.ok;
  
  // Remove any existing toast
  var existing = document.querySelector('.pm-toast');
  if (existing) existing.remove();
  
  var t = document.createElement('div');
  t.className = 'pm-toast';
  t.style.cssText = [
    'position:fixed', 'bottom:1.5rem', 'right:1.5rem', 'z-index:99999',
    'background:' + col.bg, 'color:' + col.text,
    'font-family:var(--mono,monospace)', 'font-size:.72rem', 'font-weight:700',
    'padding:.65rem 1.1rem', 'border-radius:8px',
    'box-shadow:0 4px 20px rgba(0,0,0,.4)',
    'max-width:340px', 'line-height:1.4',
    'animation:toastIn .25s ease',
    'cursor:pointer'
  ].join(';');
  t.textContent = msg;
  t.onclick = function() { t.remove(); };
  
  // Add CSS animation if not present
  if (!document.getElementById('toastStyles')) {
    var style = document.createElement('style');
    style.id = 'toastStyles';
    style.textContent = '@keyframes toastIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}@keyframes toastOut{from{opacity:1}to{opacity:0;transform:translateY(4px)}}';
    document.head.appendChild(style);
  }
  
  document.body.appendChild(t);
  setTimeout(function() {
    if (t.parentNode) {
      t.style.animation = 'toastOut .3s ease forwards';
      setTimeout(function() { if (t.parentNode) t.remove(); }, 300);
    }
  }, 3500);
}

/* ── scoreColor — converts score to color string ──────────── */
function scoreColor(score) {
  if (score >= 90) return 'var(--ok, #22e3ff)';
  if (score >= 75) return '#66dd88';
  if (score >= 55) return 'var(--warn, #f5a623)';
  if (score >= 35) return '#ff8c42';
  return 'var(--danger, #ff4d6a)';
}

function scoreGrade(score) {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 55) return 'D';
  return 'F';
}

/* ── renderRemediationError — AI fix error display ────────── */
function renderRemediationError(msg) {
  var bodyEl = document.getElementById('remModalBody');
  if (bodyEl) {
    bodyEl.innerHTML = '<div style="font-family:var(--mono);font-size:.65rem;color:var(--danger, #ff4d6a);padding:1.2rem;background:rgba(255,59,92,.06);border:1px solid rgba(255,59,92,.15);border-radius:6px;line-height:1.7">'
      + '<strong>&#9888; Cannot generate AI fix:</strong><br/>' + msg
      + '<br/><br/><span style="color:var(--muted)">Ensure ANTHROPIC_API_KEY is set in your Railway environment variables.</span>'
      + '</div>';
  }
}

/* ── discoverNetwork — network discovery wrapper ───────────── */
function discoverNetwork() {
  var modal = document.getElementById('discoverModal');
  if (modal) {
    modal.style.display = 'flex';
  } else if (typeof showToast === 'function') {
    showToast('Network discovery requires backend connection', 'info');
  }
}

/* ── Incident modal helpers ─────────────────────────────────── */
function openIncidentModal() {
  var modal = document.getElementById('incidentModal');
  if (modal) modal.style.display = 'flex';
}
function closeIncidentModal() {
  var modal = document.getElementById('incidentModal');
  if (modal) modal.style.display = 'none';
}

/* ── IOC modal helpers ───────────────────────────────────────── */
function openIocModal() {
  var modal = document.getElementById('iocModal');
  if (modal) modal.style.display = 'flex';
}
function closeIocModal() {
  var modal = document.getElementById('iocModal');
  if (modal) modal.style.display = 'none';
}

/* ── addIocEntry — save IOC from modal ───────────────────────── */
function addIocEntry() {
  var value    = (document.getElementById('iocValue') || {}).value || '';
  var severity = (document.getElementById('iocSeverity') || {}).value || 'high';
  var desc     = (document.getElementById('iocDesc') || {}).value || '';
  var source   = (document.getElementById('iocSource') || {}).value || 'manual';
  
  if (!value.trim()) { showToast('Enter an IOC value', 'warn'); return; }
  
  var ioc = {
    id: 'IOC-' + Date.now().toString(36).toUpperCase(),
    value: value.trim(), type: detectIocType(value),
    severity: severity, description: desc, source: source,
    addedAt: new Date().toISOString(), status: 'active'
  };
  
  var sid = typeof SESSION !== 'undefined' ? SESSION.id : 'guest';
  var iocs = JSON.parse(localStorage.getItem('pm_iocs_' + sid) || '[]');
  iocs.unshift(ioc);
  localStorage.setItem('pm_iocs_' + sid, JSON.stringify(iocs));
  
  closeIocModal();
  showToast('IOC added: ' + value.trim().slice(0, 30), 'ok');
  if (typeof renderIOCs === 'function') renderIOCs();
  if (typeof addActivity === 'function') addActivity('ok', '&#128203; IOC added: ' + value.trim().slice(0, 30), 'Just now');
}

function detectIocType(value) {
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(value)) return 'IP';
  if (/^[a-fA-F0-9]{32,64}$/.test(value)) return 'Hash';
  if (/^https?:\/\//.test(value)) return 'URL';
  if (/^[a-zA-Z0-9][a-zA-Z0-9-]*\.[a-zA-Z]{2,}/.test(value)) return 'Domain';
  if (/@/.test(value)) return 'Email';
  return 'Other';
}

/* ── createIncident — save incident from modal ───────────────── */
function createIncident() {
  var title    = (document.getElementById('incTitle') || {}).value || '';
  var severity = (document.getElementById('incSeverity') || {}).value || 'medium';
  var source   = (document.getElementById('incSource') || {}).value || 'manual';
  var devices  = (document.getElementById('incDevices') || {}).value || '';
  var desc     = (document.getElementById('incDesc') || {}).value || '';
  
  if (!title.trim()) { showToast('Enter an incident title', 'warn'); return; }
  
  var incident = {
    id: 'INC-' + Date.now().toString(36).toUpperCase(),
    title: title.trim(), severity: severity, source: source,
    devices: devices.split(',').map(function(s){ return s.trim(); }).filter(Boolean),
    description: desc, status: 'open',
    createdAt: new Date().toISOString(), updatedAt: new Date().toISOString()
  };
  
  var sid = typeof SESSION !== 'undefined' ? SESSION.id : 'guest';
  var incidents = JSON.parse(localStorage.getItem('pm_incidents_' + sid) || '[]');
  incidents.unshift(incident);
  localStorage.setItem('pm_incidents_' + sid, JSON.stringify(incidents));
  
  // Also save to backend if online
  if (typeof API_ONLINE !== 'undefined' && API_ONLINE && typeof SETTINGS !== 'undefined' && SETTINGS.apiUrl) {
    fetch(SETTINGS.apiUrl + '/api/soc/incidents', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({...incident, user_id: typeof SESSION !== 'undefined' ? SESSION.id : ''})
    }).catch(function(){});
  }
  
  closeIncidentModal();
  showToast('Incident created: ' + title.trim(), 'ok');
  if (typeof renderIncidents === 'function') renderIncidents();
  if (typeof addActivity === 'function') addActivity('warn', '&#128680; Incident created: ' + title.trim(), 'Just now');
}

/* ── MFA status check ────────────────────────────────────────── */
function checkMFAStatus() {
  var card = document.getElementById('mfaStatusCard');
  var text = document.getElementById('mfaStatusText');
  var btn  = document.getElementById('mfaSetupBtn');
  if (!card) return;
  
  card.style.display = 'block';
  var session = typeof AUTH !== 'undefined' && AUTH.getSession ? AUTH.getSession() : null;
  var mfaEnabled = session && session.mfaEnabled;
  
  if (text) {
    text.textContent = mfaEnabled ? '&#9989; Enabled and active' : '&#9888; Not configured — strongly recommended';
    text.style.color = mfaEnabled ? 'var(--ok)' : 'var(--warn)';
  }
  if (btn) {
    btn.textContent = mfaEnabled ? 'MANAGE 2FA' : 'SETUP 2FA';
  }
}

/* ── subscriptionDetails populate ──────────────────────────── */
function loadSubscriptionDetails() {
  var el = document.getElementById('subscriptionDetails');
  if (!el) return;
  el.style.display = 'block';
  
  var plan = typeof getUserPlan === 'function' ? getUserPlan() : 'free';
  var prices = {free:'$0',starter:'$19',pro:'$79',professional:'$79',enterprise:'$199'};
  var limits = {free:'3 scans/day · 1 device',starter:'20 scans/day · 10 devices',
                pro:'60 scans/day · 50 devices',professional:'60 scans/day · 50 devices',
                enterprise:'Unlimited scans · Unlimited devices'};
  
  el.innerHTML = '<div style="display:flex;align-items:center;gap:.8rem;flex-wrap:wrap">'
    + '<div><div style="font-family:var(--mono);font-size:.6rem;color:var(--muted)">CURRENT PLAN</div>'
    + '<div style="font-family:var(--mono);font-size:.85rem;color:var(--white);font-weight:700">' + plan.toUpperCase() + ' — ' + (prices[plan]||'$0') + '/mo</div></div>'
    + '<div style="margin-left:auto"><div style="font-family:var(--mono);font-size:.58rem;color:var(--muted)">' + (limits[plan]||'') + '</div>'
    + (plan === 'free' ? '<button onclick="openUpgradeModal()" class="btn btn-g btn-sm" style="margin-top:.3rem">&#9889; UPGRADE</button>' : '')
    + '</div></div>';
}

/* ── API Keys section ────────────────────────────────────────── */
function loadApiKeysSection() {
  var container = document.getElementById('apiKeysContainer');
  if (!container) return;
  container.style.display = 'block';
  container.innerHTML = '<div style="font-family:var(--mono);font-size:.65rem;color:var(--muted);line-height:1.9">'
    + '<div><strong style="color:var(--text2)">Configure API keys in Railway environment variables:</strong></div>'
    + '<div>ANTHROPIC_API_KEY → AI Analysis, AI Fix, AI Chat</div>'
    + '<div>HIBP_API_KEY → Real breach monitoring ($3.50/mo)</div>'
    + '<div>VIRUSTOTAL_API_KEY → IOC reputation (free)</div>'
    + '<div>ABUSEIPDB_API_KEY → IP reputation (free)</div>'
    + '<div>SHODAN_API_KEY → Port intelligence ($49/mo)</div>'
    + '<div>STRIPE_SECRET_KEY → Payment processing</div>'
    + '</div>';
}

/* ── Scheduled scans section ────────────────────────────────── */
function loadScheduledScans() {
  var container = document.getElementById('scheduledScansBody');
  if (!container) return;
  container.style.display = 'block';
  var sid = typeof SESSION !== 'undefined' ? SESSION.id : 'guest';
  var schedules = JSON.parse(localStorage.getItem('pm_schedules_' + sid) || '[]');
  container.innerHTML = schedules.length
    ? schedules.map(function(s) {
        return '<div style="display:flex;align-items:center;gap:.7rem;padding:.5rem 0;border-bottom:1px solid rgba(255,255,255,.04);font-family:var(--mono);font-size:.62rem">'
          + '<span style="color:var(--g2)">&#128337;</span>'
          + '<span style="color:var(--white)">' + s.host + '</span>'
          + '<span style="color:var(--muted)">' + s.frequency + '</span>'
          + '<span style="margin-left:auto;color:var(--muted)">Next: ' + (s.nextRun || 'Pending') + '</span>'
          + '</div>';
      }).join('')
    : '<div style="font-family:var(--mono);font-size:.62rem;color:var(--muted)">No scheduled scans. Use Settings to configure automatic scanning.</div>';
}

/* ── Referral panel ─────────────────────────────────────────── */
function loadReferralPanel() {
  var container = document.getElementById('referralPanel');
  if (!container) return;
  container.style.display = 'block';
  var sid = typeof SESSION !== 'undefined' ? SESSION.id : 'guest';
  var code = 'PM' + sid.toUpperCase().slice(0, 6);
  container.innerHTML = '<div style="font-family:var(--mono);font-size:.65rem;color:var(--muted);line-height:1.9">'
    + '<div style="color:var(--white);font-weight:700;margin-bottom:.4rem">Refer a friend — earn 1 month free</div>'
    + '<div style="display:flex;gap:.5rem;align-items:center">'
    + '<code style="background:rgba(34,227,255,.06);border:1px solid rgba(34,227,255,.15);border-radius:4px;padding:.3rem .7rem;color:var(--g);flex:1">' + code + '</code>'
    + '<button onclick="navigator.clipboard.writeText(\'' + code + '\').then(function(){showToast(\'Code copied!\',\'ok\');})" class="btn btn-o btn-sm">COPY</button>'
    + '</div>'
    + '<div style="margin-top:.3rem">Share your code. When they sign up and pay, you both get 1 month free.</div>'
    + '</div>';
}

/* ── Init: run all page-level loaders after nav ─────────────── */
/* nav hook registry - nav() handles all hooks */

/* ── Run on initial load ─────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', function() {
  setTimeout(function() {
    checkMFAStatus();
    loadScoreTrend && loadScoreTrend();
    loadRealThreatFeed && loadRealThreatFeed();
    updateScanQuotaDisplay && updateScanQuotaDisplay();
  }, 1500);
});

/* ── escHtml — sanitize user content before innerHTML ────── */
function escHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/[/]/g, '&#x2F;');
}

/* ── safeName — escape user name/hostname for display ─────── */
function safeName(str) { return escHtml(String(str || '').slice(0, 100)); }
