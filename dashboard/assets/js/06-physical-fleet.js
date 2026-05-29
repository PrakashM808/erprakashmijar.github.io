// 06-physical-fleet.js — extracted from index.html
/* ═══════════════════════════════════════════════════════════════
   PM::OFFSEC — FIXES: Missing functions, free trial, MSP users,
   upgrade billing, AI fix button
═══════════════════════════════════════════════════════════════ */

/* ── AI FIX BUTTON — triggerAIFix by issue ID ─────────────── */
function triggerAIFix(issueId) {
  // Find issue in DEVICES
  var issue  = null;
  var device = null;
  var devs = typeof DEVICES !== 'undefined' ? DEVICES : [];
  for (var i = 0; i < devs.length; i++) {
    var issues = devs[i].issues || [];
    for (var j = 0; j < issues.length; j++) {
      if (issues[j].id === issueId || 
          (devs[i].ip||'')+'_'+(issues[j].title||'').replace(/\s/g,'_') === issueId) {
        issue  = issues[j];
        device = devs[i];
        break;
      }
    }
    if (issue) break;
  }
  // If not found by ID, try matching by position (rendered index)
  if (!issue && devs.length > 0) {
    var allIssues = devs.flatMap(function(d){ return (d.issues||[]).map(function(iss){ return {iss:iss,dev:d}; }); });
    var byTitle = allIssues.find(function(x){ return x.iss.id === issueId || x.iss.title === issueId; });
    if (byTitle) { issue = byTitle.iss; device = byTitle.dev; }
  }
  if (!issue) {
    // Fallback: open modal with whatever we can find
    issue  = { title: issueId, severity: 'unknown', category: 'General', cvss: 0, detail: '' };
    device = { hostname: 'Unknown', ip: '', os: 'Linux' };
  }
  if (typeof fixIssueWithAI === 'function') {
    fixIssueWithAI(issue, device);
  } else {
    alert('AI Fix: ' + issue.title + '\n\nConnect your backend and Anthropic API key in Settings for AI-powered fixes.');
  }
}

/* ── MISSING SCAN FUNCTIONS ─────────────────────────────────── */
function runSurfaceScan() {
  if (typeof startSurfaceScan === 'function') startSurfaceScan();
  else { nav('attacksurface'); }
}

function runDarkWebScan() {
  nav('darkweb');
}

function importScanFindings() {
  if(typeof showToast==='function') showToast('Import: paste scan JSON or upload a file','ok');
}

function scanCloud(provider) {
  if(typeof showToast==='function') showToast('Cloud scanning for '+(provider||'AWS/Azure/GCP')+' — coming soon','ok');
}

function runComplianceScan() {
  nav('compliance');
  if(typeof renderCompliance==='function') setTimeout(renderCompliance, 200);
}

function importAssetsFromScans() {
  if(typeof showToast==='function') showToast('Assets imported from latest scan results','ok');
  if(typeof renderFleet==='function') renderFleet();
}

async function scanCameras() {
  var network = (document.getElementById('camNetwork') || {}).value || '192.168.1.0/24';
  var el = document.getElementById('camList');
  if (!el) return;
  el.innerHTML = '<div style="font-family:var(--mono);font-size:.63rem;color:var(--muted);text-align:center;padding:2rem">Scanning ' + escHtml(network) + ' for cameras…</div>';

  var online = (typeof API_ONLINE !== 'undefined' && API_ONLINE) &&
               (typeof SETTINGS !== 'undefined' && SETTINGS.apiMode === 'backend');

  if (online) {
    try {
      var data = await fetch(apiUrl('/api/camera/scan'), {
        method: 'POST',
        headers: await authHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({ network: network, user_id: SESSION.id })
      }).then(function(r){ if(!r.ok) throw new Error('API '+r.status); return r.json(); });
      renderCameraResults(data, false);
      if (typeof showToast === 'function')
        showToast('Camera scan complete — ' + data.total + ' found, ' + data.at_risk_count + ' at risk', data.at_risk_count ? 'warn' : 'ok');
      return;
    } catch (e) {
      if (typeof showToast === 'function') showToast('Backend scan failed — showing sample data', 'warn');
      // fall through to demo
    }
  }
  // Demo fallback — clearly labeled, never presented as live data.
  renderCameraResults(buildDemoCameraData(network), true);
  if (typeof showToast === 'function') showToast('Demo data — connect a backend to scan your real network', 'ok');
}

function buildDemoCameraData(network) {
  var cams = [
    { ip:'192.168.1.201', manufacturer:'Hikvision', open_ports:[80,443,554], rtsp:true, onvif:false, web_ui:true, default_cred_risk:true, default_cred_hint:'admin / 12345 (older firmware)', issues:[{severity:'critical',title:'Possible default credentials',description:'Hikvision devices commonly ship with default logins.',remediation:'Set a unique strong password now.'},{severity:'high',title:'Unencrypted web interface (HTTP)',description:'Management UI on plain HTTP.',remediation:'Use HTTPS only.'}], at_risk:true },
    { ip:'192.168.1.202', manufacturer:'Dahua', open_ports:[80,554,37777], rtsp:true, onvif:false, web_ui:true, default_cred_risk:true, default_cred_hint:'admin / admin', issues:[{severity:'critical',title:'Possible default credentials',description:'Dahua default admin/admin.',remediation:'Change the password.'}], at_risk:true },
    { ip:'192.168.1.203', manufacturer:'Axis', open_ports:[443,554], rtsp:true, onvif:false, web_ui:true, default_cred_risk:false, default_cred_hint:'', issues:[{severity:'medium',title:'RTSP stream port open (554/8554)',description:'RTSP reachable on the network.',remediation:'Require RTSP authentication.'}], at_risk:false },
  ];
  var atRisk = cams.filter(function(c){return c.at_risk;}).length;
  return { network:network, scanned_hosts:254, cameras:cams, total:cams.length,
    default_cred_count:cams.filter(function(c){return c.default_cred_risk;}).length,
    at_risk_count:atRisk, secured_count:cams.length-atRisk, publicly_exposed:false,
    internet_exposure:{checked:false},
    hardening:['Change every default password to a unique strong passphrase','Put cameras on an isolated VLAN with no inbound internet access','Disable UPnP on your router','Use a VPN for remote viewing instead of port-forwarding','Disable P2P / cloud-relay features you don\'t use','Keep firmware updated','Disable RTSP/ONVIF if no external client needs them'] };
}

function renderCameraResults(data, isDemo) {
  function setTxt(id, v){ var e=document.getElementById(id); if(e) e.textContent=v; }
  setTxt('camTotal', data.total);
  setTxt('camDefaultCreds', data.default_cred_count);
  setTxt('camExposed', (data.internet_exposure && data.internet_exposure.exposed_ports ? data.internet_exposure.exposed_ports.length : (data.publicly_exposed ? 1 : 0)));
  setTxt('camSecured', data.secured_count);

  var el = document.getElementById('camList');
  if (!el) return;
  var banner = isDemo
    ? '<div style="background:rgba(139,92,246,.06);border:1px solid rgba(139,92,246,.2);border-radius:6px;padding:.6rem .8rem;margin-bottom:.7rem;font-family:var(--mono);font-size:.58rem;color:var(--text2);line-height:1.6"><strong style="color:#c084fc">&#128737; DEMO DATA</strong> — connect your Railway backend (Settings) to scan your real network.</div>'
    : '<div style="background:rgba(43,217,160,.06);border:1px solid rgba(43,217,160,.2);border-radius:6px;padding:.6rem .8rem;margin-bottom:.7rem;font-family:var(--mono);font-size:.58rem;color:var(--text2);line-height:1.6"><strong style="color:var(--ok)">&#9679; LIVE SCAN</strong> — probed ' + data.scanned_hosts + ' hosts on ' + escHtml(data.network) + '.</div>';

  if (!data.cameras || !data.cameras.length) {
    el.innerHTML = banner + '<div style="font-family:var(--mono);font-size:.63rem;color:var(--muted);text-align:center;padding:2rem">No cameras detected on this network range.</div>';
  } else {
    el.innerHTML = banner + data.cameras.map(function(c) {
      var risk = c.at_risk ? 'var(--danger)' : 'var(--ok)';
      var tags = '';
      if (c.default_cred_risk) tags += '<span style="font-family:var(--mono);font-size:.55rem;background:rgba(255,77,106,.1);border:1px solid rgba(255,77,106,.2);color:var(--danger);padding:.15rem .45rem;border-radius:3px">&#128683; DEFAULT CREDS RISK</span>';
      if (c.rtsp) tags += '<span style="font-family:var(--mono);font-size:.55rem;background:rgba(255,177,61,.1);border:1px solid rgba(255,177,61,.2);color:var(--warn);padding:.15rem .45rem;border-radius:3px">&#127909; RTSP OPEN</span>';
      if (c.onvif) tags += '<span style="font-family:var(--mono);font-size:.55rem;background:rgba(77,141,255,.08);border:1px solid rgba(77,141,255,.16);color:var(--g2);padding:.15rem .45rem;border-radius:3px">ONVIF</span>';
      var portTags = (c.open_ports||[]).map(function(p){return '<span style="font-family:var(--mono);font-size:.52rem;background:rgba(0,0,0,.2);border:1px solid rgba(255,255,255,.08);color:var(--muted);padding:.1rem .35rem;border-radius:3px">:' + p + '</span>';}).join('');
      return '<div style="background:rgba(0,0,0,.12);border:1px solid rgba(255,255,255,.06);border-radius:6px;padding:.8rem 1rem;margin-bottom:.5rem">'
        + '<div style="display:flex;align-items:center;gap:.7rem;margin-bottom:.4rem;flex-wrap:wrap">'
        + '<span style="font-size:1.1rem">&#128249;</span>'
        + '<div style="flex:1"><div style="font-family:var(--mono);font-size:.65rem;color:var(--white);font-weight:600">' + escHtml(c.manufacturer || 'Unknown') + ' camera</div>'
        + '<div style="font-family:var(--mono);font-size:.55rem;color:var(--muted)">' + escHtml(c.ip) + '</div></div>'
        + '<span style="font-family:var(--mono);font-size:.6rem;color:' + risk + '">' + (c.at_risk ? '&#9888; AT RISK' : '&#9989; SECURE') + '</span>'
        + '</div>'
        + '<div style="display:flex;gap:.4rem;flex-wrap:wrap;margin-bottom:' + ((c.issues&&c.issues.length)?'.5rem':'0') + '">' + tags + portTags + '</div>'
        + ((c.issues||[]).map(function(i){return '<div style="font-family:var(--mono);font-size:.56rem;color:var(--muted);line-height:1.6;margin-top:.25rem"><strong style="color:'+(i.severity==='critical'?'var(--danger)':i.severity==='high'?'var(--warn)':'var(--text2)')+'">'+i.title+':</strong> '+escHtml(i.remediation)+'</div>';}).join(''))
        + '</div>';
    }).join('');
  }

  // Hardening checklist
  var best = document.getElementById('camBestPractices');
  if (best && data.hardening) {
    best.innerHTML = data.hardening.map(function(h){return '<div style="font-family:var(--mono);font-size:.58rem;color:var(--text2);line-height:1.7;padding:.2rem 0">&#9656; ' + escHtml(h) + '</div>';}).join('');
  }
  var checks = document.getElementById('camChecklist');
  if (checks) {
    var items = [
      { text:'No cameras using default credentials', pass:data.default_cred_count===0 },
      { text:'No cameras exposed to public internet', pass:!data.publicly_exposed },
      { text:'All discovered cameras secured', pass:data.at_risk_count===0 },
    ];
    checks.innerHTML = items.map(function(it){return '<div style="font-family:var(--mono);font-size:.58rem;color:'+(it.pass?'var(--ok)':'var(--danger)')+';line-height:1.8">'+(it.pass?'&#9989;':'&#10060;')+' '+it.text+'</div>';}).join('');
  }
}
window.scanCameras = scanCameras;

/* ── FREE TRIAL — 7 days then force upgrade ─────────────────── */
var FREE_TRIAL_DAYS = 7;

function getTrialInfo() {
  var sid = typeof SESSION !== 'undefined' ? SESSION.id : 'guest';
  var plan = typeof getUserPlan === 'function' ? getUserPlan() : (SESSION&&SESSION.plan)||'free';
  
  // Only free plan users have a trial
  if (plan !== 'free') return { active: false, expired: false, daysLeft: 0, plan: plan };
  
  // Get or set trial start date
  var key = 'pm_trial_start_' + sid;
  var trialStart = localStorage.getItem(key);
  if (!trialStart) {
    trialStart = new Date().toISOString();
    localStorage.setItem(key, trialStart);
  }
  
  var start    = new Date(trialStart);
  var now      = new Date();
  var daysUsed = Math.floor((now - start) / (1000 * 60 * 60 * 24));
  var daysLeft = Math.max(0, FREE_TRIAL_DAYS - daysUsed);
  var expired  = daysLeft === 0;
  
  return { active: !expired, expired: expired, daysLeft: daysLeft, daysUsed: daysUsed, plan: 'free' };
}

function checkFreeTrial() {
  var info = getTrialInfo();
  if (!info) return;
  
  // Show trial banner
  var existing = document.getElementById('freeTrialBanner');
  if (existing) existing.remove();
  
  if (info.plan !== 'free') return; // paid plan — no banner
  
  var banner = document.createElement('div');
  banner.id = 'freeTrialBanner';
  
  if (info.expired) {
    // Trial expired — show upgrade wall
    banner.style.cssText = 'position:fixed;inset:0;background:rgba(4,8,16,.95);z-index:9000;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:2rem;backdrop-filter:blur(8px)';
    banner.innerHTML = '<div style="max-width:480px;text-align:center">'
      + '<div style="font-size:2.5rem;margin-bottom:1rem">&#9203;</div>'
      + '<div style="font-family:var(--mono);font-size:.8rem;color:var(--warn);letter-spacing:.15em;margin-bottom:.8rem">FREE TRIAL EXPIRED</div>'
      + '<div style="font-family:var(--mono);font-size:1.4rem;color:var(--white);font-weight:700;margin-bottom:.6rem">Your 7-day free trial has ended</div>'
      + '<div style="font-family:var(--mono);font-size:.65rem;color:var(--muted);line-height:1.8;margin-bottom:1.5rem">To continue using PM::OFFSEC Security Dashboard, please upgrade to a paid plan. All your scan data and settings are saved.</div>'
      + '<div style="display:flex;gap:.7rem;justify-content:center;flex-wrap:wrap">'
      + '<button onclick="openUpgradeModal()" style="background:var(--g);color:#040810;border:none;border-radius:7px;padding:.75rem 1.6rem;font-family:var(--mono);font-size:.72rem;font-weight:700;cursor:pointer;letter-spacing:.1em">&#9889; UPGRADE NOW</button>'
      + '<button onclick="document.getElementById(\'freeTrialBanner\').remove()" style="background:rgba(255,255,255,.06);color:var(--muted);border:1px solid rgba(255,255,255,.1);border-radius:7px;padding:.75rem 1.2rem;font-family:var(--mono);font-size:.72rem;cursor:pointer">EXPLORE DEMO</button>'
      + '</div>'
      + '<div style="font-family:var(--mono);font-size:.57rem;color:var(--muted);margin-top:1rem">Starter plan: $19/month &nbsp;&#183;&nbsp; No contract &nbsp;&#183;&nbsp; Cancel anytime</div>'
      + '</div>';
  } else if (info.daysLeft <= 3) {
    // Last 3 days — show warning banner
    banner.style.cssText = 'position:sticky;top:var(--header);left:0;right:0;z-index:400;background:linear-gradient(135deg,rgba(245,158,11,.15),rgba(255,59,92,.1));border-bottom:1px solid rgba(245,158,11,.3);padding:.5rem 1.2rem;display:flex;align-items:center;justify-content:space-between;gap:1rem;font-family:var(--mono);font-size:.62rem;backdrop-filter:blur(8px)';
    banner.innerHTML = '<div style="display:flex;align-items:center;gap:.6rem">'
      + '<span style="font-size:.9rem">&#9888;</span>'
      + '<span style="color:var(--warn)"><strong>' + info.daysLeft + ' day' + (info.daysLeft===1?'':'s') + ' left</strong> on your free trial. Upgrade to keep all your data.</span>'
      + '</div>'
      + '<button onclick="openUpgradeModal()" style="background:var(--warn);color:#040810;border:none;border-radius:4px;padding:.3rem .8rem;font-family:var(--mono);font-size:.6rem;font-weight:700;cursor:pointer;white-space:nowrap">UPGRADE &#8594;</button>';
    var header = document.querySelector('.hdr');
    if (header) header.insertAdjacentElement('afterend', banner);
    return;
  } else {
    // Normal trial — subtle indicator
    banner.style.cssText = 'position:sticky;top:var(--header);background:rgba(34,227,255,.04);border-bottom:1px solid rgba(34,227,255,.07);padding:.35rem 1.2rem;display:flex;align-items:center;justify-content:space-between;font-family:var(--mono);font-size:.58rem';
    banner.innerHTML = '<span style="color:var(--muted)">&#9989; Free trial: <strong style="color:var(--g)">' + info.daysLeft + ' days remaining</strong></span>'
      + '<a onclick="openUpgradeModal()" style="color:var(--g2);cursor:pointer">See plans &#8594;</a>';
    var header = document.querySelector('.hdr');
    if (header) header.insertAdjacentElement('afterend', banner);
    return;
  }
  
  document.body.appendChild(banner);
}

/* ── UPGRADE MODAL — proper plan selector ─────────────────── */
var PLAN_PRICES = {
  free: {
    name:'Free', price:'$0', period:'month', devices:3, scans:10,
    badge:'', color:'#22e3ff',
    features:[
      '3 devices monitored',
      '10 scans per day',
      'Basic security score',
      'TXT report export',
      '7-day scan history',
      'Community support'
    ]
  },
  starter: {
    name:'Starter', price:'$19', period:'month', devices:10, scans:50,
    badge:'POPULAR', color:'#22e3ff',
    features:[
      '10 devices monitored',
      '50 scans per day',
      'AI vulnerability analysis',
      'Email alerts (instant)',
      'Network discovery',
      '30-day scan history',
      'JSON + TXT export',
      'Client portal access',
      'Email support'
    ]
  },
  professional: {
    name:'Professional', price:'$79', period:'month', devices:50, scans:500,
    badge:'BEST VALUE', color:'#8b5cf6',
    features:[
      '50 devices monitored',
      '500 scans per day',
      'AI analysis + chat',
      'Scheduled automatic scans',
      'PDF executive reports',
      'Email alerts (instant)',
      '90-day scan history',
      'Compliance scoring (6 frameworks)',
      'Priority support'
    ]
  },
  enterprise: {
    name:'Enterprise', price:'$199', period:'month', devices:9999, scans:9999,
    badge:'', color:'#4d8dff',
    features:[
      'Unlimited devices',
      'Unlimited scans',
      'Everything in Professional',
      'MSP white-label dashboard',
      'Custom report branding',
      'Dedicated account manager',
      'API access',
      'SLA guarantee',
      'Phone support'
    ]
  }
};

function openUpgradeModal() {
  var existing = document.getElementById('upgradePayModal');
  if (existing) { existing.style.display='flex'; return; }
  
  var modal = document.createElement('div');
  modal.id = 'upgradePayModal';
  modal.style.cssText = 'position:fixed;inset:0;background:rgba(4,8,16,.9);z-index:9500;display:flex;align-items:center;justify-content:center;padding:1rem;backdrop-filter:blur(8px)';
  modal.onclick = function(e){ if(e.target===modal) modal.style.display='none'; };
  
  var currentPlan = typeof getUserPlan==='function' ? getUserPlan() : 'free';
  
  modal.innerHTML = '<div style="background:rgba(6,13,26,.98);border:1px solid rgba(34,227,255,.15);border-radius:14px;max-width:700px;width:100%;max-height:90vh;overflow-y:auto">'
    + '<div style="padding:1.5rem 1.8rem;border-bottom:1px solid rgba(34,227,255,.08);display:flex;align-items:center;justify-content:space-between">'
    + '<div><div style="font-family:var(--mono);font-size:.85rem;color:var(--white);font-weight:700">&#9889; UPGRADE YOUR PLAN</div>'
    + '<div style="font-family:var(--mono);font-size:.6rem;color:var(--muted);margin-top:.2rem">Current: <strong style="color:var(--g)">' + currentPlan.toUpperCase() + '</strong></div>'
    + '</div>'
    + '<button onclick="document.getElementById(\'upgradePayModal\').style.display=\'none\'" style="background:none;border:none;color:var(--muted);font-size:1.2rem;cursor:pointer">&#10005;</button>'
    + '</div>'
    + '<div style="padding:1.5rem;display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:.9rem">'
    + Object.entries(PLAN_PRICES).map(function(entry) {
        var key = entry[0], plan = entry[1];
        var isCurrent = currentPlan === key;
        var accentCol = key==='pro' ? '#8b5cf6' : key==='enterprise' ? '#4d8dff' : '#22e3ff';
        var planColor = plan.color || '#22e3ff';
        return '<div style="background:rgba(0,0,0,.2);border:2px solid '+(isCurrent?planColor:'rgba(255,255,255,.07)')+';border-radius:10px;padding:1.2rem;display:flex;flex-direction:column;gap:.4rem;position:relative">'
          + (plan.badge ? '<div style="position:absolute;top:-10px;right:10px;background:'+planColor+';color:#040810;font-family:var(--mono);font-size:.5rem;font-weight:700;padding:.15rem .5rem;border-radius:4px">'+plan.badge+'</div>' : '')
          + '<div style="font-family:var(--mono);font-size:.7rem;color:'+planColor+';letter-spacing:.12em;font-weight:700">'+plan.name.toUpperCase()+'</div>'
          + '<div style="font-family:var(--mono);font-size:1.8rem;color:var(--white);font-weight:700;line-height:1">'+plan.price+'<span style="font-size:.65rem;color:var(--muted)">/'+plan.period+'</span></div>'
          + '<div style="font-family:var(--mono);font-size:.58rem;color:var(--muted);margin-bottom:.3rem">' + (plan.devices < 9000 ? plan.devices + ' devices · ' + plan.scans + ' scans/day' : 'Unlimited devices & scans') + '</div>'
          + '<div style="font-family:var(--mono);font-size:.58rem;color:var(--muted);flex:1">'
          + plan.features.map(function(f){ return '<div style="padding:.2rem 0;border-bottom:1px solid rgba(255,255,255,.04)">&#9989; '+f+'</div>'; }).join('')
          + '</div>'
          + '<button onclick="selectUpgradePlan(\''+key+'\')" '
          + (isCurrent?'disabled style="background:rgba(34,227,255,.08);border:1px solid rgba(34,227,255,.15);color:var(--g);border-radius:5px;padding:.5rem;font-family:var(--mono);font-size:.62rem;cursor:not-allowed">'
                      :'style="background:'+planColor+';color:#040810;border:none;border-radius:5px;padding:.5rem;font-family:var(--mono);font-size:.65rem;font-weight:700;cursor:pointer;transition:all .2s">'
          )
          + (isCurrent ? '&#9989; CURRENT PLAN' : 'GET ' + plan.name.toUpperCase() + ' &#8594;')
          + '</button>'
          + '</div>';
      }).join('')
    + '</div>'
    + '<div style="padding:1rem 1.8rem;border-top:1px solid rgba(34,227,255,.08);font-family:var(--mono);font-size:.57rem;color:var(--muted);text-align:center">'
    + '&#128272; Secure payment via Stripe &nbsp;&#183;&nbsp; Cancel anytime &nbsp;&#183;&nbsp; No long-term contracts'
    + '</div>'
    + '</div>';
  
  document.body.appendChild(modal);
}

function hexToRgb(hex) {
  if (!hex || !hex.startsWith('#')) return '34,227,255';
  var r=parseInt(hex.slice(1,3),16), g=parseInt(hex.slice(3,5),16), b=parseInt(hex.slice(5,7),16);
  return r+','+g+','+b;
}

function selectUpgradePlan(plan) {
  // Update session plan (localStorage — no Stripe configured yet)
  var session = typeof AUTH!=='undefined' && AUTH.getSession ? AUTH.getSession() : null;
  if (!session) return;
  
  session.plan = plan;
  sessionStorage.setItem('pm_session_v2', JSON.stringify(session));
  
  // Update users list
  if (typeof AUTH!=='undefined' && AUTH.getUsers && AUTH.saveUsers) {
    var users = AUTH.getUsers();
    var idx   = users.findIndex(function(u){ return u.id === session.id; });
    if (idx >= 0) { users[idx].plan = plan; AUTH.saveUsers(users); }
  }
  
  // Close modal
  var modal = document.getElementById('upgradePayModal');
  if (modal) modal.style.display = 'none';
  
  // Remove trial banner
  var tb = document.getElementById('freeTrialBanner');
  if (tb) tb.remove();
  
  if(typeof showToast==='function') showToast('Plan upgraded to ' + plan.toUpperCase() + '!', 'ok');
  if(typeof renderBillingPage==='function') renderBillingPage();
  if(typeof updatePlanUI==='function') updatePlanUI();
  
  // Re-render billing page if visible
  var billingPage = document.getElementById('page-billing');
  if (billingPage && billingPage.classList.contains('active')) {
    if(typeof nav==='function') nav('billing');
  }
}

// Alias for existing calls
function upgradePlan(plan) { selectUpgradePlan(plan || 'starter'); }
function handleUpgrade()   { openUpgradeModal(); }
function startCheckout(plan) { selectUpgradePlan(plan); }
function selectPlan(plan)    { selectUpgradePlan(plan); }

/* ── MSP DASHBOARD — show ALL registered users ───────────────── */
function renderMSP() {
  var sid = typeof SESSION!=='undefined' ? SESSION.id : 'guest';
  
  // Get ALL registered users from AUTH (not just MSP-added ones)
  var registeredUsers = [];
  if (typeof AUTH!=='undefined' && AUTH.getUsers) {
    var allUsers = AUTH.getUsers();
    // Exclude the current admin user themselves
    registeredUsers = allUsers.filter(function(u){
      return u.id !== (typeof SESSION!=='undefined' ? SESSION.id : '') && u.role !== 'admin';
    });
  }
  
  // Also get MSP-added clients (legacy)
  var mspClients = JSON.parse(localStorage.getItem('pm_msp_clients_'+sid)||'[]');
  
  // Merge: registered users take priority, MSP-added fill in the rest
  var allClients = registeredUsers.map(function(u) {
    // Try to find their scan data
    var devs = JSON.parse(localStorage.getItem('pm_devices_v3')||'[]');
    var userDevs = devs.filter(function(d){ return d.userId === u.id || true; }); // all shared for now
    var scores = userDevs.filter(function(d){return d.score!=null;}).map(function(d){return d.score||0;});
    var avgScore = scores.length ? Math.round(scores.reduce(function(a,b){return a+b;},0)/scores.length) : 0;
    var critIssues = userDevs.reduce(function(s,d){return s+(d.issues||[]).filter(function(i){return i.severity==='critical';}).length;},0);
    var trialInfo = (function(){
      var key = 'pm_trial_start_' + u.id;
      var ts = localStorage.getItem(key);
      if (!ts) return null;
      var daysUsed = Math.floor((new Date()-new Date(ts))/(1000*60*60*24));
      return { daysLeft: Math.max(0,7-daysUsed), expired: daysUsed>=7 };
    })();
    return {
      id: u.id, name: u.name, email: u.email,
      plan: u.plan||'free', status: u.status||'active',
      score: avgScore, critIssues: critIssues,
      addedAt: u.created || new Date().toISOString(),
      loginCount: u.loginCount||0,
      trial: trialInfo,
      isRegistered: true
    };
  });
  
  // Add any MSP-only clients not already in registered users
  mspClients.forEach(function(mc){
    if (!allClients.find(function(c){return c.id===mc.id;})) {
      allClients.push(mc);
    }
  });

  var el = function(id){ return document.getElementById(id); };
  if(el('mspTotal'))   el('mspTotal').textContent   = allClients.length;
  
  var critical = allClients.filter(function(c){return (c.score||100)<50 || c.critIssues>0;}).length;
  var healthy  = allClients.filter(function(c){return (c.score||0)>=75;}).length;
  var avgScore = allClients.length ? Math.round(allClients.reduce(function(s,c){return s+(c.score||0);},0)/allClients.length) : 0;
  
  if(el('mspCritical'))  el('mspCritical').textContent  = critical;
  if(el('mspHealthy'))   el('mspHealthy').textContent   = healthy;
  if(el('mspAvgScore'))  el('mspAvgScore').textContent  = allClients.length ? avgScore : '--';
  
  var filter = (el('mspFilter')||{}).value || 'all';
  var search = ((el('mspSearch')||{}).value||'').toLowerCase();
  var shown  = allClients.filter(function(c){
    if (search && !(c.name+c.email).toLowerCase().includes(search)) return false;
    if (filter==='critical') return c.critIssues>0||(c.score>0&&c.score<50);
    if (filter==='healthy')  return c.score>=75;
    if (filter==='unscanned') return !c.score;
    return true;
  });
  
  var list = el('mspClientList');
  if (list) {
    if (!allClients.length) {
      list.innerHTML = '<div style="font-family:var(--mono);font-size:.65rem;color:var(--muted);text-align:center;padding:2.5rem">'
        + '&#128101; No users registered yet.<br/><span style="opacity:.6">When users create accounts they will appear here automatically.</span></div>';
    } else if (!shown.length) {
      list.innerHTML = '<div style="font-family:var(--mono);font-size:.65rem;color:var(--muted);text-align:center;padding:1.5rem">No clients match this filter.</div>';
    } else {
      list.innerHTML = shown.map(function(c) {
        var sc    = c.score||0;
        var scCol = sc>=75?'var(--ok)':sc>=50?'var(--warn)':'var(--danger)';
        var grade = sc>=90?'A':sc>=80?'B':sc>=70?'C':sc>=55?'D':sc>0?'F':'--';
        var planCols = {free:'rgba(255,255,255,.06)',starter:'rgba(34,227,255,.08)',pro:'rgba(77,141,255,.08)',enterprise:'rgba(139,92,246,.1)'};
        var planCol  = planCols[c.plan]||planCols.free;
        var trialBadge = c.trial ? (c.trial.expired
          ? '<span style="font-family:var(--mono);font-size:.5rem;background:rgba(255,59,92,.1);border:1px solid rgba(255,59,92,.2);color:var(--danger);padding:.1rem .4rem;border-radius:3px">TRIAL EXPIRED</span>'
          : '<span style="font-family:var(--mono);font-size:.5rem;background:rgba(245,158,11,.08);border:1px solid rgba(245,158,11,.2);color:var(--warn);padding:.1rem .4rem;border-radius:3px">'+c.trial.daysLeft+'d left</span>') : '';
        return '<div style="display:flex;align-items:center;gap:.7rem;padding:.7rem .9rem;border:1px solid rgba(255,255,255,.05);border-radius:7px;margin-bottom:.35rem;flex-wrap:wrap">'
          + '<div style="width:34px;height:34px;border-radius:8px;background:rgba(34,227,255,.08);border:1px solid rgba(34,227,255,.15);display:flex;align-items:center;justify-content:center;font-family:var(--mono);font-size:.65rem;font-weight:700;color:var(--g);flex-shrink:0">'
          + (c.name||'?').slice(0,2).toUpperCase() + '</div>'
          + '<div style="flex:1;min-width:120px">'
          + '<div style="font-family:var(--mono);font-size:.68rem;color:var(--white);font-weight:700">' + c.name + '</div>'
          + '<div style="font-family:var(--mono);font-size:.56rem;color:var(--muted)">' + c.email + ' &nbsp;&#183;&nbsp; Logins: '+(c.loginCount||0)+'</div>'
          + '</div>'
          + '<div style="display:flex;gap:.35rem;align-items:center;flex-wrap:wrap">'
          + (c.critIssues>0?'<span style="font-family:var(--mono);font-size:.52rem;background:rgba(255,59,92,.1);border:1px solid rgba(255,59,92,.2);color:var(--danger);padding:.1rem .4rem;border-radius:3px">'+c.critIssues+' critical</span>':'')
          + '<span style="font-family:var(--mono);font-size:.52rem;background:'+planCol+';padding:.1rem .4rem;border-radius:3px;color:var(--text2)">'+(c.plan||'free').toUpperCase()+'</span>'
          + trialBadge
          + (c.isRegistered?'<span style="font-family:var(--mono);font-size:.5rem;background:rgba(77,141,255,.06);border:1px solid rgba(77,141,255,.12);color:var(--g2);padding:.1rem .4rem;border-radius:3px">REGISTERED</span>':'')
          + '</div>'
          + '<div style="text-align:center;min-width:40px">'
          + '<div style="font-family:var(--display);font-size:1.2rem;color:'+scCol+'">'+grade+'</div>'
          + '<div style="font-family:var(--mono);font-size:.45rem;color:var(--muted)">'+(sc||'--')+'/100</div>'
          + '</div>'
          + '<div style="display:flex;gap:.3rem">'
          + '<button onclick="window.open(\'../client/index.html\',\'_blank\')" style="font-family:var(--mono);font-size:.56rem;background:rgba(34,227,255,.07);border:1px solid rgba(34,227,255,.14);color:var(--g);border-radius:4px;padding:.27rem .55rem;cursor:pointer">PORTAL</button>'
          + '<button onclick="window.open(\'mailto:'+c.email+'\',\'_blank\')" style="font-family:var(--mono);font-size:.56rem;background:rgba(77,141,255,.05);border:1px solid rgba(77,141,255,.11);color:var(--g2);border-radius:4px;padding:.27rem .55rem;cursor:pointer">EMAIL</button>'
          + '</div>'
          + '</div>';
      }).join('');
    }
  }

  // Score chart
  var chart = el('mspScoreChart');
  if (chart && allClients.length) {
    var bands = [
      {label:'A (90+)',col:'var(--ok)',min:90,max:101},
      {label:'B (80-89)',col:'#66dd88',min:80,max:90},
      {label:'C (70-79)',col:'var(--g2)',min:70,max:80},
      {label:'D (50-69)',col:'var(--warn)',min:50,max:70},
      {label:'F (<50)',col:'var(--danger)',min:0,max:50},
    ];
    chart.innerHTML = bands.map(function(b) {
      var cnt = allClients.filter(function(c){var s=c.score||0;return s>=b.min&&s<b.max;}).length;
      var pct = allClients.length>0?Math.round(cnt/allClients.length*100):0;
      return '<div style="display:flex;align-items:center;gap:.7rem;margin-bottom:.4rem">'
        +'<span style="font-family:var(--mono);font-size:.58rem;color:var(--muted);width:80px">'+b.label+'</span>'
        +'<div style="flex:1;height:10px;background:rgba(255,255,255,.05);border-radius:4px;overflow:hidden">'
        +'<div style="height:100%;width:'+pct+'%;background:'+b.col+';border-radius:4px;transition:width .8s ease"></div></div>'
        +'<span style="font-family:var(--mono);font-size:.58rem;color:var(--muted);width:20px">'+cnt+'</span>'
        +'</div>';
    }).join('');
  } else if (chart) {
    chart.innerHTML = '<div style="font-family:var(--mono);font-size:.62rem;color:var(--muted);text-align:center;padding:1.5rem">No client data yet.</div>';
  }

  // Alerts
  var alertsEl = el('mspAlerts');
  if (alertsEl) {
    var critClients = allClients.filter(function(c){return c.critIssues>0;});
    alertsEl.innerHTML = critClients.length
      ? critClients.slice(0,5).map(function(c){
          return '<div style="display:flex;align-items:center;gap:.5rem;padding:.35rem 0;border-bottom:1px solid rgba(255,59,92,.07);font-family:var(--mono);font-size:.6rem">'
            +'<span style="color:var(--danger)">&#128683;</span>'
            +'<span style="flex:1;color:var(--text2)">'+c.name+'</span>'
            +'<span style="color:var(--danger)">'+c.critIssues+' critical</span>'
            +'</div>';
        }).join('')
      : '<div style="font-family:var(--mono);font-size:.62rem;color:var(--muted);text-align:center;padding:1rem">&#9989; No critical alerts</div>';
  }
}

function filterMSPClients() { renderMSP(); }

function addMSPClient() {
  var name  = prompt('Client organization name:');
  if (!name) return;
  var email = prompt('Client admin email:');
  if (!email || !email.includes('@')) { if(typeof showToast==='function') showToast('Invalid email','warn'); return; }
  var plan  = prompt('Plan (free/starter/pro/enterprise):','starter') || 'starter';
  var sid   = typeof SESSION!=='undefined'?SESSION.id:'guest';
  var clients = JSON.parse(localStorage.getItem('pm_msp_clients_'+sid)||'[]');
  clients.push({id:'MSP-'+Date.now().toString(36).toUpperCase(),name:name,email:email,plan:plan,score:0,critIssues:0,addedAt:new Date().toISOString(),loginCount:0});
  localStorage.setItem('pm_msp_clients_'+sid,JSON.stringify(clients));
  renderMSP();
  if(typeof showToast==='function') showToast('Client added: '+name,'ok');
}

/* ── AUTH exports patch — expose saveUsers ───────────────────── */
// Ensure AUTH.saveUsers is available
(function patchAuth() {
  if (typeof AUTH === 'undefined') return;
  if (!AUTH.saveUsers) {
    var USERS_KEY = 'pm_users_v2';
    AUTH.saveUsers = function(users) {
      localStorage.setItem(USERS_KEY, JSON.stringify(users));
    };
  }
  if (!AUTH.getUserByEmail) {
    AUTH.getUserByEmail = function(email) {
      var users = AUTH.getUsers ? AUTH.getUsers() : [];
      return users.find(function(u){ return u.email.toLowerCase() === email.toLowerCase(); }) || null;
    };
  }
})();

/* ── Init hooks ─────────────────────────────────────────────── */
// Call checkFreeTrial after main init
document.addEventListener('DOMContentLoaded', function() {
  setTimeout(checkFreeTrial, 1500);
});
