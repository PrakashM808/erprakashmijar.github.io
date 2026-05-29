// 08-patches.js — extracted from index.html
/* ═══════════════════════════════════════════════════════════════
   FINAL LAUNCH FIXES — All missing functions
═══════════════════════════════════════════════════════════════ */

/* ── Missing onclick handlers ─────────────────────────────── */
function startDiscover() {
  var btn = document.getElementById('discoverBtn');
  if (btn) btn.textContent = '⟳ SCANNING...';
  if (typeof discoverNetwork === 'function') discoverNetwork();
  else if (typeof openDiscoverModal === 'function') openDiscoverModal();
  else if(typeof showToast==='function') showToast('Network discovery requires backend connection','ok');
}

function startThreatHunt() {
  if(typeof showToast==='function') showToast('AI Threat Hunt started — analyzing scan data for attack patterns...','ok');
  var resultsEl = document.getElementById('huntResults');
  if (!resultsEl) return;
  var devices = typeof DEVICES !== 'undefined' ? DEVICES : [];
  var allIssues = devices.flatMap(function(d){ return d.issues||[]; });
  if (!allIssues.length) {
    resultsEl.innerHTML = '<div style="font-family:var(--mono);font-size:.65rem;color:var(--muted);text-align:center;padding:2rem">Run scans first to enable threat hunting.</div>';
    return;
  }
  // Build threat hunting analysis
  var critIssues = allIssues.filter(function(i){ return i.severity==='critical'; });
  var patterns = [];
  if (critIssues.some(function(i){ return i.category==='SSH'; }))
    patterns.push({name:'Lateral Movement Risk',tactic:'TA0008',severity:'critical',detail:'SSH misconfiguration could allow attackers to move between systems'});
  if (critIssues.some(function(i){ return (i.title||'').includes('CVE'); }))
    patterns.push({name:'Known Exploit Available',tactic:'TA0002',severity:'critical',detail:'Unpatched CVE with public exploit code detected'});
  if (allIssues.some(function(i){ return (i.title||'').toLowerCase().includes('firewall'); }))
    patterns.push({name:'Defense Evasion',tactic:'TA0005',severity:'high',detail:'Firewall gaps may allow attacker traffic to go undetected'});
  patterns.push({name:'No anomalous patterns',tactic:'TA0043',severity:'low',detail:'No active attack chains detected in current scan data'});
  
  resultsEl.innerHTML = patterns.map(function(p) {
    var col = p.severity==='critical'?'var(--danger)':p.severity==='high'?'var(--warn)':'var(--ok)';
    return '<div style="border:1px solid rgba(255,255,255,.06);border-left:3px solid '+col+';border-radius:6px;padding:.8rem 1rem;margin-bottom:.4rem">'
      +'<div style="display:flex;align-items:center;gap:.6rem;margin-bottom:.2rem">'
      +'<span class="badge b-'+p.severity+'">'+p.severity.toUpperCase()+'</span>'
      +'<span style="font-family:var(--mono);font-size:.68rem;color:var(--white);font-weight:700">'+p.name+'</span>'
      +'<span style="font-family:var(--mono);font-size:.58rem;color:var(--muted);margin-left:auto">'+p.tactic+'</span>'
      +'</div>'
      +'<div style="font-family:var(--mono);font-size:.6rem;color:var(--muted)">'+p.detail+'</div>'
      +'</div>';
  }).join('');
}

function viewClientReport(clientId) {
  window.open('../client/index.html', '_blank');
}

/* ── AI Fix endpoint backend call ─────────────────────────── */
async function fixIssueWithAI(issue, device) {
  currentRemIssue  = issue;
  currentRemDevice = device;
  allRemCommands   = [];
  var modal = document.getElementById('remModal');
  if (!modal) return;
  modal.style.display = 'flex';

  var titleEl = document.getElementById('remModalTitle');
  var subEl   = document.getElementById('remModalSub');
  var bodyEl  = document.getElementById('remModalBody');
  if (titleEl) titleEl.textContent = '🤖 AI FIX — ' + (issue.title||'').toUpperCase();
  if (subEl)   subEl.textContent   = (issue.category||'') + ' · CVSS ' + (issue.cvss||0) + ' · ' + (issue.severity||'').toUpperCase();
  if (bodyEl)  bodyEl.innerHTML    = '<div style="text-align:center;padding:2.5rem"><div style="display:inline-block;width:24px;height:24px;border:2px solid rgba(34,227,255,.2);border-top-color:var(--g);border-radius:50%;animation:spin .7s linear infinite"></div><div style="font-family:var(--mono);font-size:.65rem;color:var(--muted);margin-top:1rem">Claude is analyzing this vulnerability...</div></div>';

  try {
    var result = null;
    // Try backend first
    if (typeof API_ONLINE !== 'undefined' && API_ONLINE && typeof SETTINGS !== 'undefined' && SETTINGS.apiUrl) {
      var resp = await fetch(SETTINGS.apiUrl + '/api/ai/fix', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ issue: issue, device: device, user_id: typeof SESSION!=='undefined'?SESSION.id:'demo' })
      });
      if (resp.ok) result = await resp.json();
    }
    // Fallback: call Claude API directly from client
    if (!result) {
      result = await callClaudeForFix(issue, device);
    }
    renderAIFixResult(result, bodyEl);
  } catch(e) {
    if (bodyEl) bodyEl.innerHTML = '<div style="font-family:var(--mono);font-size:.65rem;color:var(--danger);padding:1rem">Error: ' + e.message + '<br/><br/>Connect backend with ANTHROPIC_API_KEY to enable AI fixes.</div>';
  }
}

async function callClaudeForFix(issue, device) {
  var prompt = 'You are a Linux security engineer. Fix this vulnerability:\n\n'
    + 'Issue: ' + issue.title + '\n'
    + 'Severity: ' + issue.severity + ' (CVSS ' + issue.cvss + ')\n'
    + 'Category: ' + issue.category + '\n'
    + 'Detail: ' + issue.detail + '\n'
    + 'OS: ' + (device.os||'Linux') + '\n'
    + 'Hostname: ' + (device.hostname||device.ip||'server') + '\n\n'
    + 'Respond ONLY with valid JSON (no markdown):\n'
    + '{"explanation":"plain English explanation","commands":["cmd1","cmd2"],"verify":"command to verify fix","risk":"low|medium|high","time":"estimated time","reboot":false}';

  var resp = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 1000,
      messages: [{ role: 'user', content: prompt }]
    })
  });
  if (!resp.ok) throw new Error('API returned ' + resp.status);
  var data = await resp.json();
  var text = (data.content||[]).map(function(c){ return c.text||''; }).join('');
  try {
    return JSON.parse(text.replace(/```json?|```/g,'').trim());
  } catch(e) {
    return { explanation: text, commands: [], verify: '', risk: issue.severity, time: '5-10 min', reboot: false };
  }
}

function renderAIFixResult(result, bodyEl) {
  if (!bodyEl) return;
  var riskCol = result.risk==='high'?'var(--danger)':result.risk==='medium'?'var(--warn)':'var(--ok)';
  allRemCommands = result.commands || [];
  bodyEl.innerHTML = '<div style="margin-bottom:.9rem">'
    + '<div style="font-family:var(--mono);font-size:.6rem;color:var(--g);letter-spacing:.1em;margin-bottom:.4rem">EXPLANATION</div>'
    + '<div style="font-family:var(--mono);font-size:.7rem;color:var(--text);line-height:1.7">' + (result.explanation||'') + '</div>'
    + '</div>'
    + (result.commands&&result.commands.length ? '<div style="margin-bottom:.9rem">'
      + '<div style="font-family:var(--mono);font-size:.6rem;color:var(--g);letter-spacing:.1em;margin-bottom:.4rem">FIX COMMANDS</div>'
      + result.commands.map(function(cmd) {
          return '<div style="background:rgba(0,0,0,.4);border:1px solid rgba(34,227,255,.1);border-radius:5px;padding:.5rem .8rem;margin-bottom:.3rem;font-family:var(--mono);font-size:.65rem;color:var(--g2);display:flex;align-items:center;gap:.6rem">'
            + '<code style="flex:1;word-break:break-all">'+cmd+'</code>'
            + '<button onclick="navigator.clipboard.writeText('+JSON.stringify(cmd)+')" style="background:none;border:none;color:var(--muted);cursor:pointer;font-size:.7rem;flex-shrink:0">&#128203;</button>'
            + '</div>';
        }).join('')
      + '</div>' : '')
    + (result.verify ? '<div style="margin-bottom:.7rem">'
      + '<div style="font-family:var(--mono);font-size:.6rem;color:var(--g2);letter-spacing:.1em;margin-bottom:.3rem">VERIFY FIX</div>'
      + '<div style="background:rgba(0,0,0,.3);border:1px solid rgba(77,141,255,.1);border-radius:5px;padding:.4rem .7rem;font-family:var(--mono);font-size:.63rem;color:var(--g2)">' + result.verify + '</div>'
      + '</div>' : '')
    + '<div style="display:flex;gap:.7rem;flex-wrap:wrap">'
    + '<span style="font-family:var(--mono);font-size:.58rem;color:'+riskCol+'">&#9888; Fix risk: '+result.risk+'</span>'
    + '<span style="font-family:var(--mono);font-size:.58rem;color:var(--muted)">&#8987; Est. time: '+(result.time||'5 min')+'</span>'
    + (result.reboot ? '<span style="font-family:var(--mono);font-size:.58rem;color:var(--warn)">&#128260; Requires reboot</span>' : '')
    + '</div>'
    + '<div style="margin-top:.6rem;font-family:var(--mono);font-size:.55rem;color:var(--muted);background:rgba(245,158,11,.04);border:1px solid rgba(245,158,11,.1);border-radius:4px;padding:.4rem .7rem">&#9888; Review all commands before running. Test on non-production first.</div>';
}

/* ── Backend AI fix endpoint added in main.py ────────────────── */
// The /api/ai/fix endpoint is handled by the backend
// Frontend calls it with issue + device context

/* ── Ensure nav hooks for new pages ─────────────────────────── */
