// 09-final.js — extracted from index.html
/* ═══════════════════════════════════════════════════════════════
   FRONTEND UPGRADES: 90-day history, real threat feed,
   HIBP live check, GDPR controls, rate limit display
═══════════════════════════════════════════════════════════════ */

/* ── 90-day Score Trend Chart ─────────────────────────────── */
async function loadScoreTrend() {
  var chartEl = document.getElementById('trendChart');
  var trendEl = document.getElementById('trendLabel');
  if (!chartEl) return;

  var uid = typeof SESSION !== 'undefined' ? SESSION.id : 'guest';
  var data = null;

  if (typeof API_ONLINE !== 'undefined' && API_ONLINE && typeof SETTINGS !== 'undefined' && SETTINGS.apiUrl) {
    try {
      var r = await fetch(SETTINGS.apiUrl + '/api/history/' + uid + '?days=90');
      if (r.ok) data = await r.json();
    } catch(e) {}
  }

  if (!data || !data.history || !data.history.length) {
    // Build from local scan history
    var scanHistory = JSON.parse(localStorage.getItem('pm_scan_history_v3')||'[]');
    if (scanHistory.length) {
      data = {
        history: scanHistory.slice(-30).map(function(s){
          return {date: s.date||new Date(s.ts||Date.now()).toISOString().split('T')[0],
                  score: s.score||0, grade: s.grade||'F', host: s.hostname||'local'};
        }),
        trend: 'local'
      };
    } else {
      chartEl.innerHTML = '<div style="font-family:var(--mono);font-size:.62rem;color:var(--muted);text-align:center;padding:2rem">Run scans to see score trend over time.</div>';
      return;
    }
  }

  var hist    = data.history;
  var maxScore = 100;
  var w = chartEl.offsetWidth || 400;
  var h = 120;
  var pad = { l:36, r:10, t:10, b:30 };
  var innerW = w - pad.l - pad.r;
  var innerH = h - pad.t - pad.b;

  // Build SVG chart
  var pts = hist.map(function(h2, i) {
    var x = pad.l + (i / Math.max(hist.length-1, 1)) * innerW;
    var y = pad.t + (1 - h2.score/100) * innerH;
    return {x:x, y:y, score:h2.score, date:h2.date, grade:h2.grade};
  });

  var polyline = pts.map(function(p){return p.x+','+p.y;}).join(' ');
  var areaPoints = polyline + ' ' + pts[pts.length-1].x+',' +(h-pad.b)+' '+pad.l+','+(h-pad.b);

  // Color gradient by last score
  var lastScore = hist[hist.length-1].score;
  var lineCol = lastScore>=75?'#22e3ff':lastScore>=50?'#f5a623':'#ff4d6a';

  var yLabels = [0,25,50,75,100].map(function(v){
    var y = pad.t + (1-v/100)*innerH;
    return '<text x="'+(pad.l-6)+'" y="'+(y+4)+'" text-anchor="end" fill="rgba(255,255,255,.25)" font-size="8">' + v + '</text>'
      + '<line x1="'+pad.l+'" y1="'+y+'" x2="'+(w-pad.r)+'" y2="'+y+'" stroke="rgba(255,255,255,.04)"/>';
  }).join('');

  var xLabels = '';
  var step = Math.max(1, Math.floor(hist.length/5));
  for (var xi=0; xi < hist.length; xi+=step) {
    var xp = pad.l + (xi/Math.max(hist.length-1,1))*innerW;
    var lbl = hist[xi].date ? hist[xi].date.slice(5) : '';
    xLabels += '<text x="'+xp+'" y="'+(h-pad.b+14)+'" text-anchor="middle" fill="rgba(255,255,255,.25)" font-size="7">' + lbl + '</text>';
  }

  var dots = pts.map(function(p){
    var col = p.score>=75?'#22e3ff':p.score>=50?'#f5a623':'#ff4d6a';
    return '<circle cx="'+p.x+'" cy="'+p.y+'" r="3" fill="'+col+'" stroke="#040810" stroke-width="1.5">'
      + '<title>'+p.date+' — Score: '+p.score+' ('+p.grade+')</title>'
      + '</circle>';
  }).join('');

  chartEl.innerHTML = '<svg width="100%" viewBox="0 0 '+w+' '+h+'" style="overflow:visible">'
    + '<defs><linearGradient id="trendGrad" x1="0" y1="0" x2="0" y2="1">'
    + '<stop offset="0%" stop-color="'+lineCol+'" stop-opacity="0.2"/>'
    + '<stop offset="100%" stop-color="'+lineCol+'" stop-opacity="0"/>'
    + '</linearGradient></defs>'
    + yLabels + xLabels
    + '<polygon points="'+areaPoints+'" fill="url(#trendGrad)"/>'
    + '<polyline points="'+polyline+'" fill="none" stroke="'+lineCol+'" stroke-width="2.5" stroke-linejoin="round" stroke-linecap="round"/>'
    + dots
    + '</svg>';

  if (trendEl) {
    var trendMap = {improving:'&#11015; Improving',declining:'&#11014; Declining',stable:'&#8594; Stable',local:'From local history'};
    trendEl.innerHTML = '<span style="color:'+lineCol+'">' + (trendMap[data.trend]||data.trend) + '</span>';
    trendEl.style.fontFamily = 'var(--mono)';
    trendEl.style.fontSize = '.62rem';
  }
}

/* ── Real Threat Feed from Backend ───────────────────────── */
async function loadRealThreatFeed() {
  var feedEl = document.getElementById('threatFeedList');
  if (!feedEl) return;
  if (!API_ONLINE || !SETTINGS || !SETTINGS.apiUrl) return;

  try {
    var r = await fetch(SETTINGS.apiUrl + '/api/threat/feed');
    if (!r.ok) return;
    var data = await r.json();

    var html = '';

    // CISA KEV exploited CVEs
    if (data.exploited_cves && data.exploited_cves.length) {
      html += data.exploited_cves.slice(0,5).map(function(v) {
        return '<div style="display:flex;align-items:center;gap:.6rem;padding:.45rem 0;border-bottom:1px solid rgba(255,59,92,.07)">'
          + '<span style="font-family:var(--mono);font-size:.58rem;color:var(--danger);width:100px;flex-shrink:0">' + v.cve_id + '</span>'
          + '<div style="flex:1;min-width:0">'
          + '<div style="font-family:var(--mono);font-size:.62rem;color:var(--white);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">' + v.vuln_name + '</div>'
          + '<div style="font-family:var(--mono);font-size:.55rem;color:var(--muted)">' + v.vendor + ' ' + v.product + '</div>'
          + '</div>'
          + '<span style="font-family:var(--mono);font-size:.52rem;color:var(--danger);white-space:nowrap">CISA KEV</span>'
          + '</div>';
      }).join('');
    }

    // Ransomware groups
    if (data.ransomware_groups && data.ransomware_groups.length) {
      html += data.ransomware_groups.slice(0,5).map(function(g) {
        return '<div style="display:flex;align-items:center;gap:.6rem;padding:.45rem 0;border-bottom:1px solid rgba(245,158,11,.06)">'
          + '<span style="font-family:var(--mono);font-size:.58rem;color:var(--warn);width:100px;flex-shrink:0">RANSOMWARE</span>'
          + '<div style="flex:1"><div style="font-family:var(--mono);font-size:.62rem;color:var(--white)">' + g.name + '</div>'
          + '<div style="font-family:var(--mono);font-size:.55rem;color:var(--muted)">' + g.posts + ' known victims</div>'
          + '</div>'
          + '<span style="font-family:var(--mono);font-size:.52rem;color:var(--warn)">ACTIVE</span>'
          + '</div>';
      }).join('');
    }

    if (html) feedEl.innerHTML = html;
  } catch(e) {}
}

/* ── Real HIBP Breach Check ──────────────────────────────── */
async function checkEmailBreachReal(email) {
  if (!email) {
    email = prompt('Enter email to check for breaches:');
    if (!email) return;
  }
  if (!API_ONLINE || !SETTINGS || !SETTINGS.apiUrl) {
    if(typeof showToast==='function') showToast('Connect backend for real HIBP breach checking','warn');
    return;
  }

  if(typeof showToast==='function') showToast('Checking HIBP for ' + email + '...','ok');
  try {
    var r = await fetch(SETTINGS.apiUrl + '/api/threat/breach-check', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({email: email, user_id: typeof SESSION!=='undefined'?SESSION.id:''})
    });
    var data = await r.json();

    var modal = document.getElementById('breachCheckModal');
    var body  = modal ? modal.querySelector('.modal-body') : null;
    if (!modal) {
      // Show in a simple overlay
      var overlay = document.createElement('div');
      overlay.style.cssText = 'position:fixed;inset:0;background:rgba(4,8,16,.9);z-index:9000;display:flex;align-items:center;justify-content:center;padding:1rem';
      overlay.onclick = function(e){ if(e.target===overlay) overlay.remove(); };

      var box = document.createElement('div');
      box.style.cssText = 'background:rgba(6,13,26,.98);border:1px solid rgba(34,227,255,.15);border-radius:12px;max-width:560px;width:100%;max-height:80vh;overflow-y:auto;padding:1.5rem';
      box.innerHTML = buildBreachResult(email, data);
      overlay.appendChild(box);
      document.body.appendChild(overlay);
    }
  } catch(e) {
    if(typeof showToast==='function') showToast('Breach check failed: ' + e.message, 'warn');
  }
}

function buildBreachResult(email, data) {
  if (data.error && !data.demo) {
    return '<div style="font-family:var(--mono);font-size:.65rem;color:var(--danger);padding:1rem">'
      + '&#10060; Error: ' + data.error + '<br/><br/>'
      + 'Add HIBP_API_KEY to Railway environment variables.<br/>'
      + '<a href="https://haveibeenpwned.com/API/Key" target="_blank" style="color:var(--g2)">Get API key — $3.50/month &#8594;</a>'
      + '</div>';
  }

  var html = '<div style="font-family:var(--mono);margin-bottom:1rem">'
    + '<div style="font-size:.8rem;color:var(--white);font-weight:700;margin-bottom:.3rem">BREACH CHECK: ' + email + '</div>';

  if (data.demo) {
    html += '<div style="font-size:.6rem;color:var(--warn);margin-bottom:.5rem">&#9888; Demo mode — add HIBP_API_KEY for real results</div>';
  }

  if (data.breached === false) {
    html += '<div style="color:var(--ok);font-size:.72rem">&#9989; No breaches found for this email</div>';
  } else if (data.breached === true) {
    html += '<div style="color:var(--danger);font-size:.72rem;margin-bottom:.7rem">&#128683; Found in ' + data.breach_count + ' breach' + (data.breach_count!==1?'es':'') + '</div>'
      + (data.breaches||[]).map(function(b) {
          var sevCol = b.severity==='critical'?'var(--danger)':'var(--warn)';
          return '<div style="border:1px solid rgba(255,255,255,.07);border-left:3px solid '+sevCol+';border-radius:6px;padding:.6rem .8rem;margin-bottom:.4rem">'
            + '<div style="display:flex;align-items:center;gap:.5rem;margin-bottom:.2rem">'
            + '<span style="font-size:.72rem;font-weight:700;color:var(--white)">' + b.name + '</span>'
            + '<span style="font-size:.55rem;color:'+sevCol+';margin-left:auto">' + b.severity.toUpperCase() + '</span>'
            + '</div>'
            + '<div style="font-size:.6rem;color:var(--muted)">Date: ' + b.date + ' &nbsp;&#183;&nbsp; ' + (b.pwn_count||0).toLocaleString() + ' accounts</div>'
            + '<div style="font-size:.58rem;color:var(--text2);margin-top:.2rem">Exposed: ' + (b.data_classes||[]).join(', ') + '</div>'
            + '</div>';
        }).join('')
      + '<div style="margin-top:.8rem;font-size:.6rem;color:var(--muted)">Recommendation: Change passwords for affected accounts. Enable 2FA everywhere.</div>';
  }

  html += '</div><button onclick="this.closest(\'[style*=position]\').remove()" '
    + 'style="background:var(--g);color:#040810;border:none;border-radius:5px;padding:.4rem 1rem;font-family:var(--mono);font-size:.65rem;font-weight:700;cursor:pointer">CLOSE</button>';
  return html;
}

/* ── GDPR controls in Settings ─────────────────────────────── */
function openGDPRPanel() {
  var existing = document.getElementById('gdprPanel');
  if (existing) { existing.style.display='flex'; return; }

  var modal = document.createElement('div');
  modal.id = 'gdprPanel';
  modal.style.cssText = 'position:fixed;inset:0;background:rgba(4,8,16,.9);z-index:9000;display:flex;align-items:center;justify-content:center;padding:1rem;backdrop-filter:blur(8px)';
  modal.onclick = function(e){ if(e.target===modal) modal.style.display='none'; };
  modal.innerHTML = '<div style="background:rgba(6,13,26,.98);border:1px solid rgba(77,141,255,.15);border-radius:12px;max-width:520px;width:100%;padding:1.5rem">'
    + '<div style="font-family:var(--mono);font-size:.85rem;color:var(--white);font-weight:700;margin-bottom:.4rem">&#127466;&#127482; YOUR DATA RIGHTS (GDPR)</div>'
    + '<div style="font-family:var(--mono);font-size:.62rem;color:var(--muted);margin-bottom:1.2rem;line-height:1.7">You have the right to access, export, and delete all your personal data stored by PM::OFFSEC.</div>'
    + '<div style="display:flex;flex-direction:column;gap:.6rem">'
    + '<button onclick="exportMyData()" style="background:rgba(77,141,255,.08);border:1px solid rgba(77,141,255,.2);border-radius:6px;padding:.7rem 1rem;font-family:var(--mono);font-size:.65rem;color:var(--g2);cursor:pointer;text-align:left">&#128229; EXPORT MY DATA (Article 20)<br/><span style="font-size:.55rem;color:var(--muted)">Download all your scan history, audit logs, and account data as JSON</span></button>'
    + '<button onclick="deleteMyData()" style="background:rgba(255,59,92,.06);border:1px solid rgba(255,59,92,.2);border-radius:6px;padding:.7rem 1rem;font-family:var(--mono);font-size:.65rem;color:var(--danger);cursor:pointer;text-align:left">&#128465; DELETE ALL MY DATA (Article 17)<br/><span style="font-size:.55rem;color:var(--muted)">Permanently erase all your data. This cannot be undone.</span></button>'
    + '</div>'
    + '<button onclick="document.getElementById(\'gdprPanel\').style.display=\'none\'" style="margin-top:1rem;background:none;border:1px solid rgba(255,255,255,.1);border-radius:5px;padding:.4rem 1rem;font-family:var(--mono);font-size:.62rem;color:var(--muted);cursor:pointer;width:100%">CLOSE</button>'
    + '</div>';
  document.body.appendChild(modal);
}

async function exportMyData() {
  if (!API_ONLINE || !SETTINGS || !SETTINGS.apiUrl) {
    if(typeof showToast==='function') showToast('Connect backend to export data','warn'); return;
  }
  try {
    var r = await fetch(SETTINGS.apiUrl + '/api/gdpr/export-my-data', {
      headers: {'Authorization': 'Bearer ' + (localStorage.getItem('pm_jwt_token')||'')}
    });
    var data = await r.json();
    var blob = new Blob([JSON.stringify(data, null, 2)], {type:'application/json'});
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'pm-offsec-my-data-' + new Date().toISOString().split('T')[0] + '.json';
    a.click();
    if(typeof showToast==='function') showToast('Data exported successfully','ok');
  } catch(e) {
    if(typeof showToast==='function') showToast('Export failed: '+e.message,'warn');
  }
}

async function deleteMyData() {
  if (!confirm('This will PERMANENTLY delete ALL your data:\n- All scan results\n- Scan history\n- Incidents and alerts\n- Scheduled scans\n\nThis cannot be undone. Are you sure?')) return;
  if (!confirm('FINAL CONFIRMATION: Delete everything?')) return;

  if (!API_ONLINE || !SETTINGS || !SETTINGS.apiUrl) {
    // Clear localStorage at minimum
    var keys = Object.keys(localStorage).filter(function(k){ return k.startsWith('pm_'); });
    keys.forEach(function(k){ localStorage.removeItem(k); });
    if(typeof showToast==='function') showToast('Local data cleared. Connect backend to delete server data.','ok');
    return;
  }
  try {
    var r = await fetch(SETTINGS.apiUrl + '/api/gdpr/delete-my-data', {
      method: 'DELETE',
      headers: {'Authorization': 'Bearer ' + (localStorage.getItem('pm_jwt_token')||'')}
    });
    var data = await r.json();
    if (data.ok) {
      // Clear local storage too
      var keys = Object.keys(localStorage).filter(function(k){ return k.startsWith('pm_'); });
      keys.forEach(function(k){ localStorage.removeItem(k); });
      if(typeof showToast==='function') showToast('All data deleted. Logging out...','ok');
      setTimeout(function(){ window.location.href = '../login.html'; }, 2000);
    }
  } catch(e) {
    if(typeof showToast==='function') showToast('Deletion failed: '+e.message,'warn');
  }
}

/* ── Rate limit display ─────────────────────────────────────── */
async function updateScanQuotaDisplay() {
  var quotaEl = document.getElementById('scanQuotaDisplay');
  if (!quotaEl || !API_ONLINE || !SETTINGS || !SETTINGS.apiUrl) return;
  try {
    var plan = typeof getUserPlan === 'function' ? getUserPlan() : 'free';
    var limits = {free:3, starter:20, pro:60, professional:60, enterprise:999};
    var limit = limits[plan] || 3;
    var used  = parseInt(localStorage.getItem('pm_scan_count_v3')||'0');
    var pct   = Math.min(100, Math.round(used/limit*100));
    var col   = pct>80?'var(--danger)':pct>50?'var(--warn)':'var(--ok)';
    quotaEl.innerHTML = '<span style="font-family:var(--mono);font-size:.6rem;color:'+col+'">'
      + used + '/' + limit + ' scans today</span>';
  } catch(e) {}
}

/* ── Init hooks ─────────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', function() {
  setTimeout(function() {
    loadScoreTrend();
    loadRealThreatFeed();
    updateScanQuotaDisplay();
  }, 2000);
});

/* ── selectUpgradePlan ───────────────────────────────────────── */
function selectUpgradePlan(planKey) {
  var plan = PLAN_PRICES[planKey];
  if (!plan) return;
  var current = typeof getUserPlan === 'function' ? getUserPlan() : 'free';
  if (planKey === current) {
    if (typeof showToast === 'function') showToast('You are already on the ' + plan.name + ' plan', 'info');
    return;
  }
  // Free plan — no payment needed
  if (planKey === 'free') {
    if (typeof showToast === 'function') showToast('Downgrade request sent. Contact support to confirm.', 'ok');
    var modal = document.getElementById('upgradePayModal');
    if (modal) modal.style.display = 'none';
    return;
  }
  // Redirect to backend checkout or billing page
  if (typeof API_ONLINE !== 'undefined' && API_ONLINE && typeof SETTINGS !== 'undefined' && SETTINGS.apiUrl) {
    var session = typeof SESSION !== 'undefined' ? SESSION : null;
    var uid = session ? (session.id || session.user_id || '') : '';
    var email = session ? (session.email || '') : '';
    if (typeof showToast === 'function') showToast('Redirecting to secure checkout for ' + plan.name + '...', 'ok');
    setTimeout(function() {
      window.location.href = SETTINGS.apiUrl + '/api/billing/checkout?plan=' + planKey + '&user_id=' + encodeURIComponent(uid) + '&email=' + encodeURIComponent(email);
    }, 800);
  } else {
    // No backend — show billing page
    if (typeof showToast === 'function') showToast('Connect your backend to enable payments', 'warn');
    var modal2 = document.getElementById('upgradePayModal');
    if (modal2) modal2.style.display = 'none';
    window.open('../billing/pricing.html', '_blank');
  }
}

/* ── hexToRgb helper ─────────────────────────────────────────── */
function hexToRgb(hex) {
  var r = parseInt(hex.slice(1,3), 16);
  var g = parseInt(hex.slice(3,5), 16);
  var b = parseInt(hex.slice(5,7), 16);
  if (isNaN(r)) return '34,227,255';  // fallback green
  return r + ',' + g + ',' + b;
}

/* ── openUpgradeModal safe wrapper ───────────────────────────── */
function openBillingModal() { openUpgradeModal(); }
