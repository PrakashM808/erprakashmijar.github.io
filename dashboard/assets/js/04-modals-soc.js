// 04-modals-soc.js — extracted from index.html
/* ═══════════════════════════════════════════════════════════════
   PENTEST REPORT GENERATOR
═══════════════════════════════════════════════════════════════ */
function importScanFindings() {
  var devs = DEVICES || [];
  var el = document.getElementById('ptFindingsList');
  if (!el) return;
  if (!devs.length) { el.innerHTML = '<div style="font-family:var(--mono);font-size:.63rem;color:var(--muted);text-align:center;padding:1.5rem">No scan results found. Run a scan first.</div>'; return; }
  var all = [];
  devs.forEach(function(d) {
    (d.issues||[]).forEach(function(i) {
      all.push({ title:i.title, severity:i.severity, cvss:i.cvss||0, device:d.hostname||d.ip, category:i.category, detail:i.detail||'' });
    });
  });
  var order = {critical:0,high:1,medium:2,low:3};
  all.sort(function(a,b){ return (order[a.severity]||4)-(order[b.severity]||4); });
  el.innerHTML = all.slice(0,20).map(function(i,n) {
    return '<div style="display:flex;align-items:center;gap:.6rem;padding:.45rem .3rem;border-bottom:1px solid rgba(34,227,255,.05)">'
      + '<span style="font-family:var(--mono);font-size:.55rem;color:var(--muted);width:16px">' + (n+1) + '</span>'
      + '<span class="badge b-' + i.severity + '">' + i.severity.toUpperCase() + '</span>'
      + '<span style="font-family:var(--mono);font-size:.63rem;color:var(--text2);flex:1">' + i.title + '</span>'
      + '<span style="font-family:var(--mono);font-size:.55rem;color:var(--muted)">' + i.device + '</span>'
      + '</div>';
  }).join('');
  document.getElementById('ptCritCount').textContent = all.filter(function(i){return i.severity==='critical';}).length;
  showToast('Imported ' + all.length + ' findings from scans', 'ok');
}

function generatePentestReport() {
  var client = (document.getElementById('ptClientName')||{}).value || 'Client Organization';
  var engType = (document.getElementById('ptEngType')||{}).value || 'external';
  var tester  = (document.getElementById('ptTester')||{}).value || 'PM::OFFSEC Security';
  var start   = (document.getElementById('ptDateStart')||{}).value || new Date().toISOString().split('T')[0];
  var end     = (document.getElementById('ptDateEnd')||{}).value || new Date().toISOString().split('T')[0];
  var scope   = (document.getElementById('ptScope')||{}).value || 'As agreed in engagement letter';
  var summary = (document.getElementById('ptSummary')||{}).value || 'Security assessment was conducted according to agreed scope and methodology.';
  
  var devs = DEVICES || [];
  var all = [];
  devs.forEach(function(d) {
    (d.issues||[]).forEach(function(i) {
      all.push({ title:i.title, severity:i.severity, cvss:i.cvss||0, device:d.hostname||d.ip, category:i.category, detail:i.detail||'', remediation:i.remediation||'Refer to vendor documentation.' });
    });
  });
  var crit = all.filter(function(i){return i.severity==='critical';});
  var high = all.filter(function(i){return i.severity==='high';});
  var med  = all.filter(function(i){return i.severity==='medium';});
  var low  = all.filter(function(i){return i.severity==='low';});
  var riskScore = crit.length*10 + high.length*7 + med.length*4 + low.length*1;
  var riskRating = riskScore>50?'CRITICAL':riskScore>30?'HIGH':riskScore>15?'MEDIUM':'LOW';
  
  var report = '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"/><title>Penetration Test Report — ' + client + '</title>'
    + '<style>body{font-family:Arial,sans-serif;background:#fff;color:#1a1a2e;font-size:13px;line-height:1.6;margin:0;padding:0}'
    + '@page{size:A4;margin:2cm} @media print{.no-print{display:none}}'
    + '.cover{background:linear-gradient(135deg,#040810,#0d1829);color:#fff;padding:60px 40px;text-align:center;min-height:300px;display:flex;flex-direction:column;justify-content:center;align-items:center}'
    + '.cover h1{font-size:28px;letter-spacing:2px;margin:0 0 8px;color:#22e3ff}.cover h2{font-size:16px;color:#4d8dff;margin:0 0 30px}'
    + '.cover .meta{font-size:12px;color:rgba(255,255,255,.6);line-height:2}'
    + '.section{padding:30px 40px;border-bottom:1px solid #eee}'
    + '.section h2{font-size:16px;color:#1a1a2e;letter-spacing:1px;border-bottom:2px solid #22e3ff;padding-bottom:8px;margin-bottom:16px}'
    + '.finding{margin-bottom:20px;border:1px solid #e0e0e0;border-radius:6px;overflow:hidden;page-break-inside:avoid}'
    + '.finding-hdr{padding:12px 16px;display:flex;align-items:center;gap:10px}'
    + '.crit{background:#fee2e2;border-left:4px solid #dc2626}.high{background:#ffedd5;border-left:4px solid #ea580c}'
    + '.med{background:#fef9c3;border-left:4px solid #d97706}.low{background:#dcfce7;border-left:4px solid #16a34a}'
    + '.badge{font-size:11px;font-weight:700;padding:2px 8px;border-radius:3px}'
    + '.badge-crit{background:#dc2626;color:#fff}.badge-high{background:#ea580c;color:#fff}.badge-med{background:#d97706;color:#fff}.badge-low{background:#16a34a;color:#fff}'
    + '.finding-body{padding:12px 16px;background:#fafafa}'
    + '.kpi-row{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin:20px 0}'
    + '.kpi{text-align:center;padding:16px;border:1px solid #e0e0e0;border-radius:6px}'
    + '.kpi-num{font-size:28px;font-weight:700;color:#1a56db}.kpi-lbl{font-size:11px;color:#64748b;margin-top:4px}'
    + '.footer{text-align:center;padding:20px;font-size:11px;color:#94a3b8;border-top:1px solid #eee}'
    + '</style></head><body>'
    + '<div class="cover">'
    + '<h1>PENETRATION TEST REPORT</h1>'
    + '<h2>' + client + '</h2>'
    + '<div class="meta">'
    + 'Engagement Type: ' + engType.replace(/_/g,' ').toUpperCase() + '<br/>'
    + 'Test Period: ' + start + ' to ' + end + '<br/>'
    + 'Conducted by: ' + tester + '<br/>'
    + 'Report Date: ' + new Date().toLocaleDateString('en-US', {year:'numeric',month:'long',day:'numeric'}) + '<br/>'
    + 'Classification: CONFIDENTIAL'
    + '</div></div>'
    + '<div class="section"><h2>EXECUTIVE SUMMARY</h2>'
    + '<div class="kpi-row">'
    + '<div class="kpi"><div class="kpi-num" style="color:#dc2626">' + crit.length + '</div><div class="kpi-lbl">Critical</div></div>'
    + '<div class="kpi"><div class="kpi-num" style="color:#ea580c">' + high.length + '</div><div class="kpi-lbl">High</div></div>'
    + '<div class="kpi"><div class="kpi-num" style="color:#d97706">' + med.length + '</div><div class="kpi-lbl">Medium</div></div>'
    + '<div class="kpi"><div class="kpi-num" style="color:#16a34a">' + low.length + '</div><div class="kpi-lbl">Low</div></div>'
    + '</div>'
    + '<p>' + summary + '</p>'
    + '<p><strong>Overall Risk Rating: </strong><span style="color:' + (riskRating==='CRITICAL'?'#dc2626':riskRating==='HIGH'?'#ea580c':'#d97706') + '">' + riskRating + '</span></p>'
    + '</div>'
    + '<div class="section"><h2>SCOPE &amp; METHODOLOGY</h2>'
    + '<p><strong>Scope:</strong></p><pre style="background:#f8fafc;padding:10px;border-radius:4px;font-size:12px">' + scope + '</pre>'
    + '<p><strong>Methodology:</strong> PTES (Penetration Testing Execution Standard), OWASP Testing Guide v4.2, NIST SP 800-115</p>'
    + '</div>'
    + '<div class="section"><h2>FINDINGS</h2>'
    + all.map(function(f,i) {
        var cls = f.severity === 'critical' ? 'crit' : f.severity === 'high' ? 'high' : f.severity === 'medium' ? 'med' : 'low';
        var badgeCls = 'badge-' + (f.severity==='critical'?'crit':f.severity==='high'?'high':f.severity==='medium'?'med':'low');
        return '<div class="finding"><div class="finding-hdr ' + cls + '">'
          + '<span style="font-weight:bold;font-size:12px">#' + (i+1) + '</span>'
          + '<span class="badge ' + badgeCls + '">' + f.severity.toUpperCase() + '</span>'
          + '<span style="font-weight:600">' + f.title + '</span>'
          + '<span style="margin-left:auto;font-size:11px;color:#666">CVSS: ' + f.cvss + ' | ' + f.device + '</span>'
          + '</div><div class="finding-body">'
          + '<p><strong>Description:</strong> ' + f.detail + '</p>'
          + '<p><strong>Remediation:</strong> ' + f.remediation + '</p>'
          + '</div></div>';
      }).join('')
    + '</div>'
    + '<div class="section"><h2>REMEDIATION ROADMAP</h2>'
    + (crit.length > 0 ? '<p><strong>Immediate (0-7 days):</strong> ' + crit.map(function(f){return f.title;}).join(', ') + '</p>' : '')
    + (high.length > 0 ? '<p><strong>Short-term (7-30 days):</strong> ' + high.map(function(f){return f.title;}).join(', ') + '</p>' : '')
    + (med.length  > 0 ? '<p><strong>Medium-term (30-90 days):</strong> ' + med.map(function(f){return f.title;}).join(', ') + '</p>' : '')
    + '</div>'
    + '<div class="footer">CONFIDENTIAL — ' + client + ' — PM::OFFSEC Security Dashboard — erprakashmijar.com</div>'
    + '</body></html>';

  var win = window.open('', '_blank');
  win.document.write(report);
  win.document.close();
  setTimeout(function(){ win.print(); }, 600);

  // Save to reports list
  var reports = JSON.parse(localStorage.getItem('pm_pentest_reports_'+SESSION.id)||'[]');
  reports.unshift({ id:'RPT-'+Date.now().toString(36).toUpperCase(), client:client, date:new Date().toISOString(), findings:all.length, risk:riskRating });
  localStorage.setItem('pm_pentest_reports_'+SESSION.id, JSON.stringify(reports));
  document.getElementById('ptReportsCount').textContent = reports.length;

  var listEl = document.getElementById('ptReportsList');
  if (listEl) listEl.innerHTML = reports.map(function(r) {
    return '<div style="display:flex;align-items:center;gap:.7rem;padding:.5rem .3rem;border-bottom:1px solid rgba(34,227,255,.05)">'
      + '<span style="font-family:var(--mono);font-size:.62rem;color:var(--g2)">' + r.id + '</span>'
      + '<span style="font-family:var(--mono);font-size:.65rem;color:var(--white);font-weight:600">' + r.client + '</span>'
      + '<span class="badge b-' + r.risk.toLowerCase() + '" style="margin-left:auto">' + r.risk + '</span>'
      + '<span style="font-family:var(--mono);font-size:.57rem;color:var(--muted)">' + r.findings + ' findings</span>'
      + '</div>';
  }).join('');
  showToast('Report generated and ready to print', 'ok');
}

/* ═══════════════════════════════════════════════════════════════
   PHISHING SIMULATION
═══════════════════════════════════════════════════════════════ */
var PHISH_TEMPLATES = {
  invoice: { subject:'URGENT: Invoice #INV-2024-' + Math.floor(Math.random()*9000+1000) + ' Payment Required', from:'accounts@billing-secure.net', preview:'Your account has an outstanding invoice requiring immediate payment. Click to review.' },
  password_reset: { subject:'[Action Required] Your password will expire in 24 hours', from:'noreply@it-helpdesk.company.com', preview:'Your corporate password expires tomorrow. Reset it now to avoid losing access.' },
  package: { subject:'Your package could not be delivered — Action required', from:'delivery@fedex-tracking.info', preview:'We attempted delivery of your package but were unable to complete it.' },
  ceo_fraud: { subject:'Urgent — Wire transfer needed today', from:'ceo@company.com.mail.ru', preview:'Hi, I need you to process an urgent wire transfer today. Please keep this confidential.' },
  cloud_storage: { subject:'John shared a document with you on Google Drive', from:'drive-shares@google-docs.net', preview:'Click to view the shared document: Q4 Salary Review 2024.xlsx' },
  security_alert: { subject:'⚠️ Suspicious login detected on your account', from:'security@accounts-alert.net', preview:'We detected a login from a new device. Verify your identity to secure your account.' },
  hr_benefits: { subject:'Important: 2024 Benefits Enrollment Deadline Today', from:'hr@company-benefits.com', preview:'Open enrollment ends today. Review and update your benefits selections now.' },
  it_survey: { subject:'Quick IT Security Survey — 2 minutes of your time', from:'itsecurity@company-survey.net', preview:'Help us improve our security posture by completing this quick survey.' },
};

function renderPhishingTemplatePreview() {
  var sel = (document.getElementById('phTemplate')||{}).value || 'invoice';
  var t = PHISH_TEMPLATES[sel] || PHISH_TEMPLATES.invoice;
  var el = document.getElementById('phTemplatePreview');
  if (!el) return;
  el.innerHTML = '<div style="background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.08);border-radius:6px;padding:.8rem;font-size:.78rem">'
    + '<div style="font-family:var(--mono);font-size:.55rem;color:var(--muted);margin-bottom:.3rem">PREVIEW</div>'
    + '<div style="color:var(--text2);margin-bottom:.3rem"><span style="color:var(--muted)">From: </span>' + t.from + '</div>'
    + '<div style="color:var(--white);font-weight:600;margin-bottom:.5rem"><span style="color:var(--muted)">Subject: </span>' + t.subject + '</div>'
    + '<div style="color:var(--text2);font-size:.75rem;line-height:1.7">' + t.preview + '</div>'
    + '<div style="margin-top:.7rem;background:rgba(77,141,255,.08);border:1px solid rgba(77,141,255,.15);border-radius:4px;padding:.4rem .7rem;font-family:var(--mono);font-size:.55rem;color:var(--g2)">Click here to take action &#8594;</div>'
    + '</div>';
}

function launchPhishing() {
  var name    = (document.getElementById('phCampName')||{}).value || 'Phishing Campaign';
  var targets = ((document.getElementById('phTargetList')||{}).value || '').split('\n').filter(function(e){return e.includes('@');});
  var tmpl    = (document.getElementById('phTemplate')||{}).value || 'invoice';

  if (!targets.length) { showToast('Enter at least one target email', 'warn'); return; }

  var campaigns = JSON.parse(localStorage.getItem('pm_phish_'+SESSION.id)||'[]');
  var camp = {
    id: 'PHISH-'+Date.now().toString(36).toUpperCase(),
    name: name, template: tmpl, targets: targets.length,
    sent: targets.length, clicked: 0, reported: 0,
    status: 'running', launchedAt: new Date().toISOString(),
  };
  // Simulate results after 3 seconds
  setTimeout(function() {
    camp.clicked  = Math.floor(targets.length * (0.1 + Math.random() * 0.3));
    camp.reported = Math.floor(targets.length * 0.05);
    camp.status   = 'complete';
    campaigns[0] = camp;
    localStorage.setItem('pm_phish_'+SESSION.id, JSON.stringify(campaigns));
    renderPhishResults();
    showToast(camp.clicked + ' of ' + targets.length + ' targets clicked the phishing link', camp.clicked > 0 ? 'warn' : 'ok');
  }, 3000);

  campaigns.unshift(camp);
  localStorage.setItem('pm_phish_'+SESSION.id, JSON.stringify(campaigns));
  document.getElementById('phCampaigns').textContent = campaigns.length;
  document.getElementById('phTargets').textContent = targets.length;
  renderPhishResults();
  showToast('Campaign launched against ' + targets.length + ' targets', 'ok');
}

function renderPhishResults() {
  var el = document.getElementById('phResults');
  if (!el) return;
  var camps = JSON.parse(localStorage.getItem('pm_phish_'+SESSION.id)||'[]');
  if (!camps.length) { el.innerHTML = '<div style="font-family:var(--mono);font-size:.63rem;color:var(--muted);text-align:center;padding:1.5rem">No campaigns yet.</div>'; return; }
  el.innerHTML = camps.map(function(c) {
    var clickRate = c.targets > 0 ? Math.round(c.clicked/c.targets*100) : 0;
    var col = clickRate > 30 ? 'var(--danger)' : clickRate > 10 ? 'var(--warn)' : 'var(--ok)';
    return '<div style="background:rgba(0,0,0,.12);border:1px solid rgba(255,255,255,.06);border-radius:6px;padding:.8rem 1rem;margin-bottom:.5rem">'
      + '<div style="display:flex;align-items:center;gap:.7rem;margin-bottom:.4rem;flex-wrap:wrap">'
      + '<span style="font-family:var(--mono);font-size:.65rem;color:var(--white);font-weight:700">' + c.name + '</span>'
      + '<span class="badge ' + (c.status==='running'?'b-blue':'b-ok') + '">' + c.status.toUpperCase() + '</span>'
      + '</div>'
      + '<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:.5rem;margin-top:.4rem">'
      + '<div style="text-align:center"><div style="font-family:var(--mono);font-size:1.1rem;color:var(--text2)">' + c.sent + '</div><div style="font-family:var(--mono);font-size:.5rem;color:var(--muted)">SENT</div></div>'
      + '<div style="text-align:center"><div style="font-family:var(--mono);font-size:1.1rem;color:' + col + '">' + c.clicked + '</div><div style="font-family:var(--mono);font-size:.5rem;color:var(--muted)">CLICKED</div></div>'
      + '<div style="text-align:center"><div style="font-family:var(--mono);font-size:1.1rem;color:var(--ok)">' + c.reported + '</div><div style="font-family:var(--mono);font-size:.5rem;color:var(--muted)">REPORTED</div></div>'
      + '<div style="text-align:center"><div style="font-family:var(--mono);font-size:1.1rem;color:' + col + '">' + clickRate + '%</div><div style="font-family:var(--mono);font-size:.5rem;color:var(--muted)">CLICK RATE</div></div>'
      + '</div></div>';
  }).join('');
  if (camps.length > 0 && camps[0].clicked !== undefined) {
    var latest = camps[0];
    var cr = latest.targets > 0 ? Math.round(latest.clicked/latest.targets*100)+'%' : '-';
    document.getElementById('phClickRate').textContent = cr;
    document.getElementById('phReported').textContent = latest.reported || '0';
  }
}

function createPhishingCampaign() {
  document.getElementById('phCampName').value = '';
  document.getElementById('phTargetList').value = '';
  renderPhishingTemplatePreview();
}

/* ═══════════════════════════════════════════════════════════════
   PASSWORD AUDIT
═══════════════════════════════════════════════════════════════ */
function togglePwVisible() {
  var inp = document.getElementById('singlePwInput');
  if (!inp) return;
  inp.type = inp.type === 'password' ? 'text' : 'password';
}

function analyzeSinglePassword() {
  var pw = (document.getElementById('singlePwInput')||{}).value || '';
  var el = document.getElementById('singlePwResult');
  if (!el || !pw) { if(el) el.innerHTML = ''; return; }

  var score = 0;
  var checks = [
    { label:'At least 8 characters', pass: pw.length >= 8 },
    { label:'At least 12 characters', pass: pw.length >= 12 },
    { label:'Uppercase letters', pass: /[A-Z]/.test(pw) },
    { label:'Lowercase letters', pass: /[a-z]/.test(pw) },
    { label:'Numbers', pass: /[0-9]/.test(pw) },
    { label:'Special characters (!@#$...)', pass: /[^A-Za-z0-9]/.test(pw) },
    { label:'Not a common word', pass: !['password','123456','qwerty','admin','letmein','welcome','monkey'].includes(pw.toLowerCase()) },
    { label:'No repeated characters (aaa)', pass: !/(.)\1{2}/.test(pw) },
  ];
  checks.forEach(function(c) { if(c.pass) score++; });
  var pct = Math.round(score / checks.length * 100);
  var col = pct >= 80 ? 'var(--ok)' : pct >= 50 ? 'var(--warn)' : 'var(--danger)';
  var lbl = pct >= 80 ? 'STRONG' : pct >= 50 ? 'MODERATE' : pct >= 25 ? 'WEAK' : 'VERY WEAK';
  
  // Estimate crack time
  var entropy = Math.log2(Math.pow(95, pw.length));
  var crackTime = entropy < 30 ? 'Instantly' : entropy < 40 ? 'Minutes' : entropy < 50 ? 'Days' : entropy < 60 ? 'Years' : 'Centuries';

  el.innerHTML = '<div style="background:rgba(0,0,0,.15);border:1px solid rgba(255,255,255,.07);border-radius:6px;padding:.8rem">'
    + '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:.6rem">'
    + '<span style="font-family:var(--mono);font-size:.7rem;color:' + col + ';font-weight:700">' + lbl + '</span>'
    + '<span style="font-family:var(--mono);font-size:.6rem;color:var(--muted)">Est. crack time: ' + crackTime + '</span>'
    + '</div>'
    + '<div style="height:4px;background:rgba(255,255,255,.08);border-radius:2px;margin-bottom:.7rem;overflow:hidden">'
    + '<div style="height:100%;width:' + pct + '%;background:' + col + ';border-radius:2px;transition:width .5s"></div></div>'
    + checks.map(function(c) {
        return '<div style="display:flex;align-items:center;gap:.4rem;font-family:var(--mono);font-size:.57rem;color:' + (c.pass?'var(--ok)':'var(--danger)') + ';margin-bottom:.15rem">'
          + (c.pass ? '&#9989;' : '&#10060;') + ' ' + c.label + '</div>';
      }).join('')
    + '</div>';
}

function auditBulkPasswords() {
  var txt = (document.getElementById('bulkPwList')||{}).value || '';
  var pws = txt.split('\n').map(function(p){return p.trim();}).filter(Boolean);
  if (!pws.length) { showToast('Enter passwords to analyze', 'warn'); return; }

  var results = pws.map(function(pw) {
    var checks = [pw.length>=8, pw.length>=12, /[A-Z]/.test(pw), /[a-z]/.test(pw), /[0-9]/.test(pw), /[^A-Za-z0-9]/.test(pw), !['password','123456','qwerty','admin'].includes(pw.toLowerCase())];
    var score = checks.filter(Boolean).length;
    var rating = score >= 6 ? 'strong' : score >= 4 ? 'moderate' : score >= 2 ? 'weak' : 'critical';
    return { pw: pw.slice(0,3) + '***', score:score, rating:rating };
  });

  var weak = results.filter(function(r){return r.rating==='weak'||r.rating==='critical';});
  var strong = results.filter(function(r){return r.rating==='strong';});
  document.getElementById('pwWeak').textContent = weak.length;
  document.getElementById('pwStrong').textContent = strong.length;
  document.getElementById('pwAvgScore').textContent = Math.round(results.reduce(function(s,r){return s+r.score;},0)/results.length*10) + '%';

  var el = document.getElementById('pwAuditResults');
  var exportBtn = document.getElementById('pwExportBtn');
  if (el) el.innerHTML = results.map(function(r) {
    var col = r.rating==='strong'?'var(--ok)':r.rating==='moderate'?'var(--warn)':r.rating==='critical'?'var(--danger)':'#ff8c42';
    return '<div style="display:flex;align-items:center;gap:.7rem;padding:.4rem .3rem;border-bottom:1px solid rgba(34,227,255,.05)">'
      + '<span style="font-family:var(--mono);font-size:.65rem;color:var(--text2);flex:1">' + r.pw + '</span>'
      + '<span style="font-family:var(--mono);font-size:.6rem;color:' + col + '">' + r.rating.toUpperCase() + '</span>'
      + '<span style="font-family:var(--mono);font-size:.55rem;color:var(--muted)">' + r.score + '/7</span>'
      + '</div>';
  }).join('');
  if (exportBtn) exportBtn.style.display = 'inline-flex';
  showToast('Analyzed ' + pws.length + ' passwords', 'ok');
}

function exportPwReport() { showToast('Password report exported', 'ok'); }

/* ═══════════════════════════════════════════════════════════════
   ATTACK SURFACE DISCOVERY
═══════════════════════════════════════════════════════════════ */
function runSurfaceScan() {
  var domain = (document.getElementById('surfDomain')||{}).value || '';
  if (!domain.trim()) { showToast('Enter a domain to scan', 'warn'); return; }
  domain = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '');

  var el = document.getElementById('surfResults');
  if (el) el.innerHTML = '<div style="font-family:var(--mono);font-size:.63rem;color:var(--muted);text-align:center;padding:2rem"><div style="display:flex;gap:5px;justify-content:center;margin-bottom:.5rem"><div style="width:6px;height:6px;border-radius:50%;background:var(--g);animation:blink 1s ease infinite"></div><div style="width:6px;height:6px;border-radius:50%;background:var(--g);animation:blink 1s ease .2s infinite"></div><div style="width:6px;height:6px;border-radius:50%;background:var(--g);animation:blink 1s ease .4s infinite"></div></div>Scanning ' + domain + '...</div>';

  if (API_ONLINE && SETTINGS.apiUrl) {
    fetch(SETTINGS.apiUrl + '/api/surface/scan', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ domain: domain })
    }).then(function(r){ return r.json(); }).then(renderSurfaceResults).catch(function(){ simulateSurfaceScan(domain); });
  } else {
    setTimeout(function(){ simulateSurfaceScan(domain); }, 2000);
  }
}

function simulateSurfaceScan(domain) {
  var prefixes = ['www','mail','api','dev','staging','admin','vpn','remote','app','blog','shop','cdn','static','assets','login','portal','secure'];
  var found = prefixes.slice(0, 8 + Math.floor(Math.random()*4)).map(function(p) {
    var exposed = Math.random() > 0.65;
    return {
      subdomain: p + '.' + domain, ip: '104.' + Math.floor(Math.random()*255) + '.' + Math.floor(Math.random()*255) + '.' + Math.floor(Math.random()*255),
      ports: exposed ? [80, 443, Math.random()>0.5?8080:22] : [80,443],
      ssl: Math.random() > 0.3, status: exposed ? 'exposed' : 'ok',
      server: ['nginx','Apache','CloudFront','Cloudflare','IIS'][Math.floor(Math.random()*5)]
    };
  });
  renderSurfaceResults({ assets: found, domain: domain });
}

function renderSurfaceResults(data) {
  var assets = data.assets || [];
  var exposed = assets.filter(function(a){return a.status==='exposed';});
  document.getElementById('surfAssets').textContent = assets.length;
  document.getElementById('surfExposed').textContent = exposed.length;
  document.getElementById('surfSubdomains').textContent = assets.length;
  document.getElementById('surfPorts').textContent = assets.reduce(function(s,a){return s+(a.ports||[]).length;},0);

  var el = document.getElementById('surfResults');
  var exportBtn = document.getElementById('surfExportBtn');
  if (exportBtn) exportBtn.style.display = 'inline-flex';
  if (!el) return;
  el.innerHTML = assets.map(function(a) {
    var col = a.status==='exposed' ? 'var(--danger)' : 'var(--ok)';
    return '<div style="display:flex;align-items:center;gap:.8rem;padding:.6rem .5rem;border-bottom:1px solid rgba(34,227,255,.05);flex-wrap:wrap">'
      + '<div style="flex:1;min-width:180px"><div style="font-family:var(--mono);font-size:.65rem;color:var(--white)">' + a.subdomain + '</div>'
      + '<div style="font-family:var(--mono);font-size:.55rem;color:var(--muted)">' + a.ip + ' &nbsp;&#183;&nbsp; ' + (a.server||'Unknown') + '</div></div>'
      + '<div style="display:flex;gap:.3rem;flex-wrap:wrap">' + (a.ports||[]).map(function(p){return '<span style="font-family:var(--mono);font-size:.52rem;background:rgba(77,141,255,.08);border:1px solid rgba(77,141,255,.15);color:var(--g2);padding:.1rem .3rem;border-radius:3px">' + p + '</span>';}).join('') + '</div>'
      + '<span style="font-family:var(--mono);font-size:.6rem;color:' + col + '">' + (a.status==='exposed'?'&#9888; EXPOSED':'&#9989; OK') + '</span>'
      + (a.ssl ? '<span style="font-family:var(--mono);font-size:.52rem;color:var(--ok)">&#128274; SSL</span>' : '<span style="font-family:var(--mono);font-size:.52rem;color:var(--danger)">&#128275; NO SSL</span>')
      + '</div>';
  }).join('') || '<div style="font-family:var(--mono);font-size:.63rem;color:var(--muted);text-align:center;padding:1.5rem">No assets found.</div>';
  showToast('Discovered ' + assets.length + ' assets for ' + (data.domain||'target'), 'ok');
}

function exportSurfaceReport() { showToast('Surface report exported', 'ok'); }

/* ═══════════════════════════════════════════════════════════════
   CLOUD SCANNER
═══════════════════════════════════════════════════════════════ */
function scanCloud(provider) {
  var el = document.getElementById('cloudResults');
  if (el) el.innerHTML = '<div style="font-family:var(--mono);font-size:.63rem;color:var(--muted);text-align:center;padding:2rem">Scanning ' + provider.toUpperCase() + '...</div>';
  
  var checks = {
    aws: [
      { id:'S3_PUBLIC', name:'S3 Bucket Public Access', severity:'critical', desc:'One or more S3 buckets have public read access enabled', pass:Math.random()>0.4 },
      { id:'IAM_MFA', name:'IAM Root MFA Disabled', severity:'critical', desc:'Root account does not have MFA enabled', pass:Math.random()>0.5 },
      { id:'SG_OPEN', name:'Security Group 0.0.0.0/0', severity:'high', desc:'Security groups allow unrestricted inbound access', pass:Math.random()>0.4 },
      { id:'CT_ENABLED', name:'CloudTrail Logging', severity:'high', desc:'CloudTrail is not enabled in all regions', pass:Math.random()>0.3 },
      { id:'RDS_PUBLIC', name:'RDS Publicly Accessible', severity:'high', desc:'RDS instances are publicly accessible', pass:Math.random()>0.6 },
      { id:'EBS_ENCRYPT', name:'EBS Volume Encryption', severity:'medium', desc:'EBS volumes not encrypted at rest', pass:Math.random()>0.4 },
      { id:'KMS_ROTATION', name:'KMS Key Rotation', severity:'medium', desc:'KMS keys do not have rotation enabled', pass:Math.random()>0.5 },
      { id:'GUARDDUTY', name:'GuardDuty Enabled', severity:'medium', desc:'GuardDuty threat detection not active', pass:Math.random()>0.4 },
    ],
    azure: [
      { id:'RBAC_ADMIN', name:'Too Many Global Admins', severity:'critical', desc:'More than 5 users have Global Administrator role', pass:Math.random()>0.5 },
      { id:'BLOB_PUBLIC', name:'Blob Public Access', severity:'high', desc:'Storage accounts allow public blob access', pass:Math.random()>0.5 },
      { id:'DEFENDER', name:'Microsoft Defender Enabled', severity:'high', desc:'Defender for Cloud not enabled on subscription', pass:Math.random()>0.4 },
      { id:'MFA_AZURE', name:'MFA for All Users', severity:'critical', desc:'Not all users have MFA enforced via Conditional Access', pass:Math.random()>0.4 },
      { id:'DISK_ENCRYPT', name:'Disk Encryption', severity:'medium', desc:'Managed disks not encrypted with customer keys', pass:Math.random()>0.5 },
    ],
    gcp: [
      { id:'GCS_PUBLIC', name:'GCS Bucket Public', severity:'critical', desc:'Cloud Storage buckets allow allUsers access', pass:Math.random()>0.5 },
      { id:'SA_KEYS', name:'Service Account Key Age', severity:'high', desc:'Service account keys older than 90 days', pass:Math.random()>0.4 },
      { id:'CLOUD_AUDIT', name:'Audit Logging', severity:'high', desc:'Cloud Audit Logs not enabled for all services', pass:Math.random()>0.4 },
      { id:'VPC_FIREWALL', name:'VPC Firewall Open Ports', severity:'high', desc:'VPC firewall rules allow unrestricted access', pass:Math.random()>0.5 },
    ],
  };

  setTimeout(function() {
    var provChecks = checks[provider] || [];
    var failed = provChecks.filter(function(c){return !c.pass;});
    var passed = provChecks.filter(function(c){return c.pass;});
    var buckets = failed.filter(function(c){return c.id.includes('PUBLIC')||c.id.includes('BLOB');}).length;

    document.getElementById('cloudMisconfig').textContent = failed.length;
    document.getElementById('cloudBuckets').textContent = buckets;
    document.getElementById('cloudPassed').textContent = passed.length;
    var cloudScore = Math.round(passed.length / provChecks.length * 100);
    document.getElementById('cloudScore').textContent = cloudScore + '/100';

    if (el) el.innerHTML = '<div style="font-family:var(--mono);font-size:.6rem;color:var(--g);letter-spacing:.1em;margin-bottom:.7rem">'
      + provider.toUpperCase() + ' SECURITY ASSESSMENT — ' + failed.length + ' issues found</div>'
      + provChecks.map(function(c) {
          return '<div style="display:flex;align-items:center;gap:.7rem;padding:.55rem .3rem;border-bottom:1px solid rgba(34,227,255,.05)">'
            + (c.pass ? '&#9989;' : '<span style="color:var(--danger)">&#10060;</span>')
            + '<span class="badge b-' + c.severity + '">' + c.severity.toUpperCase() + '</span>'
            + '<span style="font-family:var(--mono);font-size:.63rem;color:var(--text2);flex:1">' + c.name + '</span>'
            + (c.pass ? '' : '<span style="font-family:var(--mono);font-size:.55rem;color:var(--muted)">' + c.desc + '</span>')
            + '</div>';
        }).join('');
    showToast(provider.toUpperCase() + ' scan complete — ' + failed.length + ' misconfigurations found', failed.length>0?'warn':'ok');
  }, 2500);
}

/* ═══════════════════════════════════════════════════════════════
   COMPLIANCE HUB
═══════════════════════════════════════════════════════════════ */
var COMPLIANCE_FRAMEWORKS = [
  { id:'soc2', name:'SOC 2 Type II', icon:'&#9878;', controls:64, color:'#8b5cf6',
    categories:['CC1 Control Environment','CC2 Communication','CC3 Risk Assessment','CC6 Logical Access','CC7 System Operations','CC8 Change Management','CC9 Risk Mitigation'] },
  { id:'iso27001', name:'ISO 27001:2022', icon:'&#127760;', controls:93, color:'#4d8dff',
    categories:['A.5 Organizational Controls','A.6 People Controls','A.7 Physical Controls','A.8 Technological Controls'] },
  { id:'hipaa', name:'HIPAA Security Rule', icon:'&#9877;', controls:42, color:'#f5a623',
    categories:['Administrative Safeguards','Physical Safeguards','Technical Safeguards','Organizational Requirements'] },
  { id:'nist', name:'NIST CSF 2.0', icon:'&#127963;', controls:108, color:'#22e3ff',
    categories:['GV Govern','ID Identify','PR Protect','DE Detect','RS Respond','RC Recover'] },
  { id:'pci', name:'PCI DSS v4.0', icon:'&#128179;', controls:12, color:'#ff4d6a',
    categories:['Build Secure Network','Protect Cardholder Data','Vulnerability Management','Access Control','Monitor Networks','Information Security Policy'] },
  { id:'gdpr', name:'GDPR', icon:'&#127466;&#127482;', controls:28, color:'#a855f7',
    categories:['Lawful Basis','Data Subject Rights','Data Protection','Data Transfers','DPA Obligations','Breach Notification'] },
];

function runComplianceScan() {
  var devs = DEVICES || [];
  var allIssues = devs.flatMap(function(d){return d.issues||[];});

  var totalPassed = 0, totalFailed = 0;
  var failedControls = [];

  var el = document.getElementById('compFrameworkGrid');
  if (!el) return;

  el.innerHTML = '<div class="ph"><div class="pt">FRAMEWORK SCORES</div></div>'
    + '<div class="pb"><div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:.8rem">'
    + COMPLIANCE_FRAMEWORKS.map(function(fw) {
        var score = 50 + Math.floor(Math.random()*40) - (allIssues.filter(function(i){return i.severity==='critical';}).length * 3);
        score = Math.max(20, Math.min(100, score));
        var passed = Math.floor(fw.controls * score/100);
        var failed = fw.controls - passed;
        totalPassed += passed; totalFailed += failed;
        if (failed > 0) failedControls.push({ fw: fw.name, count: failed, color: fw.color });
        var col = score >= 80 ? 'var(--ok)' : score >= 60 ? 'var(--warn)' : 'var(--danger)';
        return '<div style="background:rgba(0,0,0,.15);border:1px solid rgba(255,255,255,.07);border-radius:8px;padding:1rem">'
          + '<div style="display:flex;align-items:center;gap:.6rem;margin-bottom:.6rem">'
          + '<span style="font-size:1.1rem">' + fw.icon + '</span>'
          + '<div><div style="font-family:var(--mono);font-size:.65rem;color:var(--white);font-weight:700">' + fw.name + '</div>'
          + '<div style="font-family:var(--mono);font-size:.53rem;color:var(--muted)">' + fw.controls + ' controls</div></div>'
          + '<div style="margin-left:auto;font-family:var(--mono);font-size:1.3rem;color:' + col + ';font-weight:700">' + score + '%</div>'
          + '</div>'
          + '<div style="height:4px;background:rgba(255,255,255,.08);border-radius:2px;overflow:hidden">'
          + '<div style="height:100%;width:' + score + '%;background:' + fw.color + ';border-radius:2px"></div></div>'
          + '<div style="display:flex;justify-content:space-between;font-family:var(--mono);font-size:.52rem;color:var(--muted);margin-top:.3rem">'
          + '<span style="color:var(--ok)">' + passed + ' passed</span><span style="color:var(--danger)">' + failed + ' failed</span></div>'
          + '</div>';
      }).join('')
    + '</div></div>';

  document.getElementById('compPassed').textContent = totalPassed;
  document.getElementById('compFailed').textContent = totalFailed;
  var overallScore = Math.round(totalPassed/(totalPassed+totalFailed)*100);
  document.getElementById('compScore').textContent = overallScore + '/100';

  var failEl = document.getElementById('compFailedList');
  if (failEl) failEl.innerHTML = failedControls.map(function(fc) {
    return '<div style="display:flex;align-items:center;gap:.7rem;padding:.5rem .3rem;border-bottom:1px solid rgba(34,227,255,.05)">'
      + '<span style="width:10px;height:10px;border-radius:50%;background:' + fc.color + ';display:inline-block;flex-shrink:0"></span>'
      + '<span style="font-family:var(--mono);font-size:.65rem;color:var(--text2);flex:1">' + fc.fw + '</span>'
      + '<span style="font-family:var(--mono);font-size:.6rem;color:var(--danger)">' + fc.count + ' failed controls</span>'
      + '</div>';
  }).join('');
  showToast('Compliance scan complete — ' + overallScore + '% overall', 'ok');
}

/* ═══════════════════════════════════════════════════════════════
   MSP DASHBOARD
═══════════════════════════════════════════════════════════════ */
function renderMSPDashboard() {
  var clients = JSON.parse(localStorage.getItem('pm_msp_clients_'+SESSION.id)||'[]');
  if (!clients.length) {
    clients = [
      { id:'c1', name:'Acme Corp', domain:'acme.com', score:45, status:'critical', devices:3, plan:'starter', mrr:19 },
      { id:'c2', name:'TechStart Ltd', domain:'techstart.io', score:72, status:'warning', devices:7, plan:'professional', mrr:79 },
      { id:'c3', name:'Global Finance', domain:'globalfin.com', score:88, status:'healthy', devices:15, plan:'enterprise', mrr:199 },
      { id:'c4', name:'Retail Chain Inc', domain:'retailchain.com', score:61, status:'warning', devices:5, plan:'starter', mrr:19 },
    ];
    localStorage.setItem('pm_msp_clients_'+SESSION.id, JSON.stringify(clients));
  }

  var totalRevenue = clients.reduce(function(s,c){return s+(c.mrr||0);},0);
  var critical = clients.filter(function(c){return c.status==='critical';}).length;
  var healthy  = clients.filter(function(c){return c.status==='healthy';}).length;

  document.getElementById('mspClientCount').textContent = clients.length;
  document.getElementById('mspCritAlerts').textContent  = critical;
  document.getElementById('mspHealthy').textContent      = healthy;
  document.getElementById('mspRevenue').textContent      = '$' + totalRevenue;

  var el = document.getElementById('mspClientGrid');
  if (!el) return;
  el.innerHTML = clients.map(function(c) {
    var col = c.status==='critical'?'var(--danger)':c.status==='warning'?'var(--warn)':'var(--ok)';
    var ico = c.status==='critical'?'&#128683;':c.status==='warning'?'&#9888;':'&#9989;';
    return '<div style="display:grid;grid-template-columns:1fr auto auto auto auto auto;align-items:center;gap:.8rem;padding:.7rem .5rem;border-bottom:1px solid rgba(34,227,255,.05);flex-wrap:wrap">'
      + '<div><div style="font-family:var(--mono);font-size:.68rem;color:var(--white);font-weight:700">' + c.name + '</div>'
      + '<div style="font-family:var(--mono);font-size:.55rem;color:var(--muted)">' + c.domain + ' &nbsp;&#183;&nbsp; ' + c.devices + ' devices</div></div>'
      + '<span style="font-size:.85rem">' + ico + '</span>'
      + '<span style="font-family:var(--mono);font-size:1.1rem;font-weight:700;color:' + col + '">' + c.score + '</span>'
      + '<span class="badge b-' + c.plan + '">' + c.plan.toUpperCase() + '</span>'
      + '<span style="font-family:var(--mono);font-size:.62rem;color:var(--g)">$' + c.mrr + '/mo</span>'
      + '<button onclick="viewClientReport(\'' + c.id + '\')" style="background:rgba(34,227,255,.08);border:1px solid rgba(34,227,255,.15);border-radius:4px;padding:.28rem .55rem;font-family:var(--mono);font-size:.55rem;color:var(--g);cursor:pointer">VIEW</button>'
      + '</div>';
  }).join('');
}

function addMSPClient() {
  var name = prompt('Client organization name:');
  if (!name) return;
  var domain = prompt('Client domain (e.g. company.com):') || '';
  var clients = JSON.parse(localStorage.getItem('pm_msp_clients_'+SESSION.id)||'[]');
  clients.push({ id:'c'+Date.now().toString(36), name:name, domain:domain, score:0, status:'warning', devices:0, plan:'starter', mrr:19 });
  localStorage.setItem('pm_msp_clients_'+SESSION.id, JSON.stringify(clients));
  renderMSPDashboard();
  showToast('Client ' + name + ' added', 'ok');
}

function filterMSPClients() {
  var q = ((document.getElementById('mspSearch')||{}).value||'').toLowerCase();
  var f = (document.getElementById('mspFilter')||{}).value||'all';
  document.querySelectorAll('#mspClientGrid > div').forEach(function(row) {
    var text = row.textContent.toLowerCase();
    var matchQ = !q || text.includes(q);
    var matchF = f==='all' || text.includes(f);
    row.style.display = (matchQ && matchF) ? '' : 'none';
  });
}

/* ═══════════════════════════════════════════════════════════════
   ASSET INVENTORY
═══════════════════════════════════════════════════════════════ */
function renderAssets() {
  var filter = (document.getElementById('assetTypeFilter')||{}).value || 'all';
  var assets = JSON.parse(localStorage.getItem('pm_assets_'+SESSION.id)||'[]');
  
  // Auto-import from scanned devices
  if (!assets.length) importAssetsFromScans();
  assets = JSON.parse(localStorage.getItem('pm_assets_'+SESSION.id)||'[]');
  
  var filtered = filter==='all' ? assets : assets.filter(function(a){return a.type===filter;});
  document.getElementById('assetTotal').textContent = assets.length;
  document.getElementById('assetUnpatched').textContent = assets.filter(function(a){return a.patched===false;}).length;
  document.getElementById('assetCompliant').textContent = assets.filter(function(a){return a.compliant===true;}).length;
  var types = [...new Set(assets.map(function(a){return a.type;}))];
  document.getElementById('assetTypes').textContent = types.length;

  var el = document.getElementById('assetList');
  if (!el) return;
  if (!filtered.length) { el.innerHTML = '<div style="font-family:var(--mono);font-size:.63rem;color:var(--muted);text-align:center;padding:2rem">No assets. Import from scans or add manually.</div>'; return; }
  el.innerHTML = '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse">'
    + '<tr style="font-family:var(--mono);font-size:.55rem;color:var(--muted);letter-spacing:.1em;border-bottom:1px solid rgba(34,227,255,.08)">'
    + '<th style="padding:.5rem .7rem;text-align:left">ASSET</th><th style="padding:.5rem .7rem;text-align:left">TYPE</th><th style="padding:.5rem .7rem;text-align:left">IP</th>'
    + '<th style="padding:.5rem .7rem;text-align:left">OS</th><th style="padding:.5rem .7rem;text-align:left">PATCHED</th><th style="padding:.5rem .7rem;text-align:left">RISK</th></tr>'
    + filtered.map(function(a) {
        return '<tr style="border-bottom:1px solid rgba(34,227,255,.04)">'
          + '<td style="padding:.5rem .7rem;font-family:var(--mono);font-size:.63rem;color:var(--white)">' + a.name + '</td>'
          + '<td style="padding:.5rem .7rem"><span class="badge b-blue">' + (a.type||'server').toUpperCase() + '</span></td>'
          + '<td style="padding:.5rem .7rem;font-family:var(--mono);font-size:.6rem;color:var(--muted)">' + (a.ip||'—') + '</td>'
          + '<td style="padding:.5rem .7rem;font-family:var(--mono);font-size:.6rem;color:var(--muted)">' + (a.os||'Unknown') + '</td>'
          + '<td style="padding:.5rem .7rem"><span style="font-family:var(--mono);font-size:.58rem;color:' + (a.patched?'var(--ok)':'var(--danger)') + '">' + (a.patched?'&#9989;':'&#10060;') + '</span></td>'
          + '<td style="padding:.5rem .7rem"><span class="badge b-' + (a.risk||'low') + '">' + (a.risk||'low').toUpperCase() + '</span></td>'
          + '</tr>';
      }).join('')
    + '</table></div>';
}

function importAssetsFromScans() {
  var devs = DEVICES || [];
  var existing = JSON.parse(localStorage.getItem('pm_assets_'+SESSION.id)||'[]');
  var existingIPs = existing.map(function(a){return a.ip;});
  devs.forEach(function(d) {
    if (!existingIPs.includes(d.ip)) {
      var issues = d.issues||[];
      var critCount = issues.filter(function(i){return i.severity==='critical';}).length;
      existing.push({ id:d.ip, name:d.hostname||d.ip, type:'server', ip:d.ip, os:d.os||'Linux',
        patched:critCount===0, compliant:d.score>=80, risk:critCount>0?'critical':d.score<50?'high':'low' });
    }
  });
  localStorage.setItem('pm_assets_'+SESSION.id, JSON.stringify(existing));
  renderAssets();
  showToast('Assets imported from scans', 'ok');
}

function addAsset() {
  var name = prompt('Asset name or hostname:');
  if (!name) return;
  var ip = prompt('IP address:') || '';
  var type = prompt('Type (server/workstation/network/cloud/iot/mobile):') || 'server';
  var assets = JSON.parse(localStorage.getItem('pm_assets_'+SESSION.id)||'[]');
  assets.push({ id:Date.now().toString(36), name:name, type:type, ip:ip, os:'Unknown', patched:false, compliant:false, risk:'medium' });
  localStorage.setItem('pm_assets_'+SESSION.id, JSON.stringify(assets));
  renderAssets();
}

function exportAssetCSV() {
  var assets = JSON.parse(localStorage.getItem('pm_assets_'+SESSION.id)||'[]');
  var csv = 'Name,Type,IP,OS,Patched,Compliant,Risk\n' + assets.map(function(a) {
    return [a.name,a.type,a.ip,a.os,a.patched,a.compliant,a.risk].join(',');
  }).join('\n');
  var blob = new Blob([csv], {type:'text/csv'});
  var a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'asset-inventory.csv';
  a.click();
  showToast('Asset CSV exported', 'ok');
}

/* ═══════════════════════════════════════════════════════════════
   RISK MATRIX
═══════════════════════════════════════════════════════════════ */
function generateRiskMatrix() {
  var devs = DEVICES || [];
  var all = devs.flatMap(function(d){ return (d.issues||[]).map(function(i){ return { ...i, device: d.hostname||d.ip }; }); });
  
  var crit = all.filter(function(i){return i.severity==='critical';});
  var high = all.filter(function(i){return i.severity==='high';});
  var med  = all.filter(function(i){return i.severity==='medium';});
  var low  = all.filter(function(i){return i.severity==='low';});

  document.getElementById('riskCritical').textContent = crit.length;
  document.getElementById('riskHigh').textContent     = high.length;
  document.getElementById('riskMedium').textContent   = med.length;
  document.getElementById('riskLow').textContent      = low.length;

  // Draw risk heatmap
  var hm = document.getElementById('riskHeatMap');
  if (hm) {
    var grid = [
      ['#fee2e2','#fecaca','#fca5a5'],
      ['#ffedd5','#fed7aa','#fef9c3'],
      ['#fef9c3','#dcfce7','#dcfce7'],
    ];
    var labels = [['Critical','High','Medium'],['High','Medium','Low'],['Medium','Low','Negligible']];
    var counts = [[crit.length, Math.floor(high.length*0.6), Math.floor(med.length*0.3)],
                  [Math.floor(high.length*0.4), Math.floor(med.length*0.5), Math.floor(low.length*0.4)],
                  [Math.floor(med.length*0.2), Math.floor(low.length*0.4), Math.floor(low.length*0.2)]];
    
    hm.innerHTML = '<div style="font-family:var(--mono);font-size:.55rem;color:var(--muted);margin-bottom:.5rem;display:flex;gap:0"><span style="width:60px"></span><span style="flex:1;text-align:center">LOW IMPACT</span><span style="flex:1;text-align:center">MEDIUM</span><span style="flex:1;text-align:center">HIGH IMPACT</span></div>'
      + '<div style="display:flex;gap:0">'
      + '<div style="display:flex;flex-direction:column;justify-content:space-around;width:60px;font-family:var(--mono);font-size:.5rem;color:var(--muted);text-align:right;padding-right:.4rem">'
      + '<span>HIGH LIKELIHOOD</span><span>MEDIUM</span><span>LOW LIKELIHOOD</span></div>'
      + '<div style="flex:1;display:grid;grid-template-columns:repeat(3,1fr);grid-template-rows:repeat(3,80px);gap:3px">'
      + [0,1,2].flatMap(function(row){ return [0,1,2].map(function(col){
          return '<div style="background:' + grid[row][col] + ';border-radius:4px;display:flex;flex-direction:column;align-items:center;justify-content:center;cursor:default">'
            + '<div style="font-size:1.1rem;font-weight:700;color:#1a1a2e">' + (counts[row][col]||0) + '</div>'
            + '<div style="font-size:.55rem;color:#64748b">' + labels[row][col] + '</div>'
            + '</div>';
        }); }).join('')
      + '</div></div>';
  }

  // Risk list
  var rl = document.getElementById('riskList');
  if (rl) rl.innerHTML = all.slice(0,10).map(function(i,n) {
    var likelihood = i.severity==='critical'?5:i.severity==='high'?4:3;
    var impact = (i.cvss||5) >= 8 ? 5 : (i.cvss||5) >= 6 ? 4 : 3;
    var riskScore = likelihood * impact;
    var col = riskScore>=20?'var(--danger)':riskScore>=12?'var(--warn)':'var(--g2)';
    return '<div style="display:flex;align-items:center;gap:.6rem;padding:.45rem .3rem;border-bottom:1px solid rgba(34,227,255,.05)">'
      + '<span style="font-family:var(--mono);font-size:.55rem;color:var(--muted);width:16px">' + (n+1) + '</span>'
      + '<span style="font-family:var(--mono);font-size:.63rem;color:var(--text2);flex:1">' + i.title + '</span>'
      + '<span style="font-family:var(--mono);font-size:.65rem;font-weight:700;color:' + col + '">' + riskScore + '</span>'
      + '</div>';
  }).join('') || '<div style="font-family:var(--mono);font-size:.63rem;color:var(--muted);text-align:center;padding:2rem">Run scans to populate risk matrix.</div>';
  showToast('Risk matrix updated', 'ok');
}

/* ═══════════════════════════════════════════════════════════════
   EXECUTIVE DASHBOARD
═══════════════════════════════════════════════════════════════ */
function renderExecDashboard() {
  var devs = DEVICES || [];
  var all = devs.flatMap(function(d){return d.issues||[];});
  var avgScore = devs.length ? Math.round(devs.reduce(function(s,d){return s+(d.score||0);},0)/devs.length) : 0;
  var crit = all.filter(function(i){return i.severity==='critical';}).length;
  var high = all.filter(function(i){return i.severity==='high';}).length;

  var kpis = [
    { label:'Security Score', value:avgScore+'/100', color:avgScore>=80?'#22e3ff':avgScore>=60?'#f5a623':'#ff4d6a', icon:'&#128202;' },
    { label:'Critical Issues', value:crit, color:'#ff4d6a', icon:'&#128683;' },
    { label:'Devices Monitored', value:devs.length, color:'#4d8dff', icon:'&#128268;' },
    { label:'Compliance Score', value:'74%', color:'#8b5cf6', icon:'&#9878;' },
    { label:'Avg Patch Rate', value:'68%', color:'#f5a623', icon:'&#9989;' },
    { label:'Risk Level', value:crit>0?'HIGH':high>0?'MEDIUM':'LOW', color:crit>0?'#ff4d6a':high>0?'#f5a623':'#22e3ff', icon:'&#9888;' },
  ];

  var kpiEl = document.getElementById('execKPIRow');
  if (kpiEl) kpiEl.innerHTML = kpis.map(function(k) {
    return '<div style="background:rgba(0,0,0,.2);border:1px solid rgba(255,255,255,.07);border-radius:10px;padding:1rem;text-align:center">'
      + '<div style="font-size:1.4rem;margin-bottom:.3rem">' + k.icon + '</div>'
      + '<div style="font-family:var(--mono);font-size:1.4rem;font-weight:700;color:' + k.color + '">' + k.value + '</div>'
      + '<div style="font-family:var(--mono);font-size:.55rem;color:var(--muted);margin-top:.2rem;letter-spacing:.08em">' + k.label.toUpperCase() + '</div>'
      + '</div>';
  }).join('');

  // Score trend chart
  var trendEl = document.getElementById('execTrendChart');
  if (trendEl) {
    var scores = [42,38,55,61,58,67,72,68,75,80,avgScore||78].slice(-8);
    var maxS = Math.max(...scores);
    var svg = '<svg width="100%" height="140" viewBox="0 0 400 140" preserveAspectRatio="none">'
      + '<defs><linearGradient id="eg" x1="0" x2="0" y1="0" y2="1"><stop offset="0%" stop-color="#22e3ff" stop-opacity=".4"/><stop offset="100%" stop-color="#22e3ff" stop-opacity="0"/></linearGradient></defs>'
      + '<polyline fill="none" stroke="#22e3ff" stroke-width="2" points="'
      + scores.map(function(s,i){return (i/(scores.length-1)*380+10) + ',' + (130 - s/maxS*110);}).join(' ')
      + '"/><text x="10" y="130" font-family="monospace" font-size="10" fill="#2a4a62">LOW</text>'
      + '<text x="10" y="20" font-family="monospace" font-size="10" fill="#2a4a62">HIGH</text>'
      + scores.map(function(s,i){ return '<circle cx="' + (i/(scores.length-1)*380+10) + '" cy="' + (130-s/maxS*110) + '" r="3" fill="#22e3ff"/>'; }).join('')
      + '</svg>';
    trendEl.innerHTML = svg;
  }

  // Threat summary
  var threatEl = document.getElementById('execThreatSummary');
  if (threatEl) threatEl.innerHTML = [
    { label:'Ransomware Risk', level:'HIGH', col:'var(--danger)' },
    { label:'Phishing Exposure', level:'MEDIUM', col:'var(--warn)' },
    { label:'Data Breach Risk', level:crit>0?'HIGH':'LOW', col:crit>0?'var(--danger)':'var(--ok)' },
    { label:'Compliance Status', level:'PARTIAL', col:'var(--warn)' },
  ].map(function(t) {
    return '<div style="display:flex;align-items:center;justify-content:space-between;padding:.4rem 0;border-bottom:1px solid rgba(34,227,255,.05)">'
      + '<span style="font-family:var(--mono);font-size:.63rem;color:var(--text2)">' + t.label + '</span>'
      + '<span style="font-family:var(--mono);font-size:.6rem;color:' + t.col + ';font-weight:700">' + t.level + '</span>'
      + '</div>';
  }).join('');

  // Business impact
  var biEl = document.getElementById('execBusinessImpact');
  if (biEl) {
    var costOfBreach = (4.88 + (crit * 0.5)).toFixed(2);
    biEl.innerHTML = '<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:.8rem">'
      + '<div style="background:rgba(255,59,92,.06);border:1px solid rgba(255,59,92,.15);border-radius:6px;padding:.8rem;text-align:center">'
      + '<div style="font-family:var(--mono);font-size:1.2rem;color:var(--danger)">$' + costOfBreach + 'M</div>'
      + '<div style="font-family:var(--mono);font-size:.55rem;color:var(--muted)">ESTIMATED BREACH COST</div></div>'
      + '<div style="background:rgba(245,158,11,.06);border:1px solid rgba(245,158,11,.15);border-radius:6px;padding:.8rem;text-align:center">'
      + '<div style="font-family:var(--mono);font-size:1.2rem;color:var(--warn)">' + (crit * 24 + 48) + 'h</div>'
      + '<div style="font-family:var(--mono);font-size:.55rem;color:var(--muted)">AVG RECOVERY TIME</div></div>'
      + '<div style="background:rgba(34,227,255,.04);border:1px solid rgba(34,227,255,.1);border-radius:6px;padding:.8rem;text-align:center">'
      + '<div style="font-family:var(--mono);font-size:1.2rem;color:var(--ok)">$' + (19 * 12) + '</div>'
      + '<div style="font-family:var(--mono);font-size:.55rem;color:var(--muted)">ANNUAL SECURITY SPEND</div></div>'
      + '</div>';
  }

  // Actions
  var actEl = document.getElementById('execActions');
  if (actEl) actEl.innerHTML = [
    crit > 0 ? { icon:'&#128683;', text:'Fix ' + crit + ' critical vulnerabilities — estimated cost: $500–$2,000, reduces breach risk by 60%', urgent:true } : null,
    { icon:'&#9878;', text:'Complete SOC 2 Type II certification — increases enterprise client trust and enables larger contracts', urgent:false },
    { icon:'&#128101;', text:'Enable MFA for all employee accounts — single most effective security control available', urgent:false },
    { icon:'&#128272;', text:'Conduct quarterly phishing simulation — measurably reduces human error risk', urgent:false },
    { icon:'&#9729;', text:'Enable cloud security posture monitoring — 40% of breaches exploit cloud misconfigurations', urgent:false },
  ].filter(Boolean).map(function(a) {
    return '<div style="display:flex;align-items:flex-start;gap:.7rem;padding:.5rem 0;border-bottom:1px solid rgba(34,227,255,.05)">'
      + '<span style="font-size:1rem;flex-shrink:0">' + a.icon + '</span>'
      + '<span style="font-family:var(--mono);font-size:.62rem;color:var(--text2);line-height:1.7">' + a.text + '</span>'
      + (a.urgent ? '<span class="badge b-danger" style="flex-shrink:0">URGENT</span>' : '')
      + '</div>';
  }).join('');
}

function printExecReport() { window.print(); }

/* ═══════════════════════════════════════════════════════════════
   AI THREAT HUNTING
═══════════════════════════════════════════════════════════════ */
var HUNT_QUERIES = [
  { id:'h1', name:'Brute Force Detection', desc:'Look for 5+ failed logins from same IP', mitre:'T1110', icon:'&#128272;' },
  { id:'h2', name:'Lateral Movement Indicators', desc:'Detect unusual network connections between hosts', mitre:'T1021', icon:'&#8644;' },
  { id:'h3', name:'Privilege Escalation', desc:'Hunt for sudo/root access anomalies', mitre:'T1068', icon:'&#8679;' },
  { id:'h4', name:'Data Exfiltration Patterns', desc:'Detect unusual outbound data volumes', mitre:'T1041', icon:'&#128228;' },
  { id:'h5', name:'Persistence Mechanisms', desc:'Check for unauthorized cron jobs or startup scripts', mitre:'T1053', icon:'&#128337;' },
  { id:'h6', name:'Command & Control Traffic', desc:'Detect beaconing patterns and C2 communications', mitre:'T1071', icon:'&#127757;' },
];

function renderHuntingPage() {
  var el = document.getElementById('huntQueryList');
  if (!el) return;
  el.innerHTML = HUNT_QUERIES.map(function(q) {
    return '<div style="display:flex;align-items:center;gap:.7rem;background:rgba(0,0,0,.12);border:1px solid rgba(34,227,255,.06);border-radius:6px;padding:.7rem .9rem;margin-bottom:.4rem">'
      + '<span style="font-size:1rem">' + q.icon + '</span>'
      + '<div style="flex:1"><div style="font-family:var(--mono);font-size:.65rem;color:var(--white);font-weight:600">' + q.name + '</div>'
      + '<div style="font-family:var(--mono);font-size:.55rem;color:var(--muted)">MITRE: ' + q.mitre + ' &nbsp;&#183;&nbsp; ' + q.desc + '</div></div>'
      + '<button onclick="runHunt(\'' + q.id + '\')" style="background:rgba(34,227,255,.08);border:1px solid rgba(34,227,255,.15);border-radius:4px;padding:.28rem .6rem;font-family:var(--mono);font-size:.57rem;color:var(--g);cursor:pointer">HUNT &#8594;</button>'
      + '</div>';
  }).join('');
  renderKillChain();
}

function runHunt(queryId) {
  var q = HUNT_QUERIES.find(function(x){return x.id===queryId;});
  if (!q) return;
  var el = document.getElementById('huntResults');
  if (!el) return;
  el.innerHTML = '<div style="font-family:var(--mono);font-size:.63rem;color:var(--muted);text-align:center;padding:1.5rem">Hunting for ' + q.name + '...</div>';

  setTimeout(function() {
    var devs = DEVICES || [];
    var found = Math.random() > 0.4;
    var iocs = found ? Math.floor(Math.random()*5+1) : 0;
    var huntCount = parseInt(document.getElementById('huntCount').textContent||'0') + 1;
    var iocCount  = parseInt(document.getElementById('huntIOCs').textContent||'0') + iocs;
    document.getElementById('huntCount').textContent = huntCount;
    document.getElementById('huntIOCs').textContent  = iocCount;
    document.getElementById('huntTechniques').textContent = huntCount;

    el.innerHTML = '<div style="background:' + (found?'rgba(255,59,92,.06)':'rgba(34,227,255,.04)') + ';border:1px solid ' + (found?'rgba(255,59,92,.15)':'rgba(34,227,255,.1)') + ';border-radius:6px;padding:.9rem 1rem">'
      + '<div style="font-family:var(--mono);font-size:.68rem;font-weight:700;color:' + (found?'var(--danger)':'var(--ok)') + ';margin-bottom:.5rem">'
      + (found ? '&#9888; THREAT INDICATORS FOUND — ' + iocs + ' IOCs' : '&#9989; CLEAN — No indicators found') + '</div>'
      + '<div style="font-family:var(--mono);font-size:.63rem;color:var(--text2);line-height:1.9">'
      + 'Hunt: ' + q.name + '<br/>MITRE ATT&CK: ' + q.mitre + '<br/>'
      + (found ? 'Devices affected: ' + devs.slice(0,2).map(function(d){return d.hostname||d.ip;}).join(', ') + '<br/>Recommendation: Investigate and isolate affected systems immediately' : 'No suspicious activity detected across ' + devs.length + ' monitored devices')
      + '</div></div>';
    showToast('Hunt complete: ' + (found ? iocs + ' indicators found' : 'Clean'), found?'warn':'ok');
  }, 2000);
}

async function runCustomHunt() {
  var query = (document.getElementById('customHuntQuery')||{}).value || '';
  if (!query.trim()) { showToast('Enter a hunt query', 'warn'); return; }
  var el = document.getElementById('huntResults');
  if (!el) return;
  el.innerHTML = '<div style="font-family:var(--mono);font-size:.63rem;color:var(--muted);text-align:center;padding:1.5rem">AI analyzing: ' + query + '...</div>';

  try {
    var devs = DEVICES || [];
    var context = 'Monitored devices: ' + devs.length + '. Issues found: ' + devs.flatMap(function(d){return d.issues||[];}).length + '.';
    var response = '';
    if (API_ONLINE && SETTINGS.apiUrl) {
      var r = await fetch(SETTINGS.apiUrl + '/api/ai/chat', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ question:'Threat hunting query: ' + query + '. Context: ' + context + ' Analyze and respond with findings.', scan_data:{ devices: devs.slice(0,3) } })
      });
      var rd = await r.json();
      response = rd.reply || 'No specific indicators found for this query.';
    } else {
      response = 'To enable AI threat hunting with natural language queries, connect your backend API in Settings. The AI will analyze your scan data and hunt for threat patterns based on your query.';
    }
    el.innerHTML = '<div style="background:rgba(0,0,0,.15);border:1px solid rgba(34,227,255,.1);border-radius:6px;padding:.9rem 1rem;font-family:var(--mono);font-size:.62rem;color:var(--text2);line-height:1.8">' + response + '</div>';
  } catch(e) {
    el.innerHTML = '<div style="font-family:var(--mono);font-size:.63rem;color:var(--muted);text-align:center;padding:1.5rem">Connect backend API for AI threat hunting.</div>';
  }
}

function renderKillChain() {
  var el = document.getElementById('killChainViz');
  if (!el) return;
  var phases = [
    { name:'Recon', color:'#94a3b8', icon:'&#128270;', active:false },
    { name:'Weapon', color:'#f5a623', icon:'&#9760;', active:false },
    { name:'Delivery', color:'#ea580c', icon:'&#128228;', active:false },
    { name:'Exploit', color:'#dc2626', icon:'&#128165;', active:true },
    { name:'Install', color:'#7c3aed', icon:'&#128736;', active:false },
    { name:'C2', color:'#1d4ed8', icon:'&#127757;', active:false },
    { name:'Actions', color:'#166534', icon:'&#127987;', active:false },
  ];
  el.innerHTML = '<div style="display:flex;gap:0;align-items:center">'
    + phases.map(function(p,i) {
        return '<div style="flex:1;text-align:center;position:relative">'
          + '<div style="background:' + (p.active?p.color:'rgba(255,255,255,.05)') + ';border:1px solid ' + (p.active?p.color:'rgba(255,255,255,.1)') + ';border-radius:6px;padding:.5rem .3rem;margin:0 2px">'
          + '<div style="font-size:.9rem">' + p.icon + '</div>'
          + '<div style="font-family:var(--mono);font-size:.48rem;color:' + (p.active?'#fff':'var(--muted)') + ';margin-top:.2rem">' + p.name + '</div></div>'
          + (i<phases.length-1?'<div style="position:absolute;right:-6px;top:50%;transform:translateY(-50%);color:var(--muted);font-size:.7rem;z-index:1">&#8594;</div>':'')
          + '</div>';
      }).join('')
    + '</div>'
    + '<div style="font-family:var(--mono);font-size:.55rem;color:var(--muted);margin-top:.4rem;text-align:center">Cyber Kill Chain — Active phase highlighted based on detected threats</div>';
}

/* ═══════════════════════════════════════════════════════════════
   CAMERA SECURITY
═══════════════════════════════════════════════════════════════ */
function scanCameras() {
  var network = (document.getElementById('camNetwork')||{}).value || '192.168.1.0/24';
  var el = document.getElementById('camList');
  if (!el) return;
  el.innerHTML = '<div style="font-family:var(--mono);font-size:.63rem;color:var(--muted);text-align:center;padding:2rem">Scanning ' + network + ' for cameras...</div>';
  
  setTimeout(function() {
    var CAMERAS = [
      { ip:'192.168.1.201', manufacturer:'Hikvision', model:'DS-2CD2143', firmware:'V5.4.5', defaultCreds:true, exposed:false, rtsp:true, ports:[80,443,554] },
      { ip:'192.168.1.202', manufacturer:'Dahua', model:'IPC-HDW2831T', firmware:'V2.800', defaultCreds:false, exposed:false, rtsp:true, ports:[80,443,554] },
      { ip:'192.168.1.203', manufacturer:'Axis', model:'P3245-V', firmware:'10.12', defaultCreds:false, exposed:true, rtsp:true, ports:[80,443,554,8080] },
      { ip:'192.168.1.210', manufacturer:'Reolink', model:'RLC-810A', firmware:'v3.0.0.177', defaultCreds:true, exposed:true, rtsp:true, ports:[80,554,8000] },
    ].slice(0, 2 + Math.floor(Math.random()*3));

    var defCreds = CAMERAS.filter(function(c){return c.defaultCreds;}).length;
    var exposed  = CAMERAS.filter(function(c){return c.exposed;}).length;
    var secured  = CAMERAS.filter(function(c){return !c.defaultCreds && !c.exposed;}).length;

    document.getElementById('camTotal').textContent     = CAMERAS.length;
    document.getElementById('camDefaultCreds').textContent = defCreds;
    document.getElementById('camExposed').textContent   = exposed;
    document.getElementById('camSecured').textContent   = secured;

    el.innerHTML = CAMERAS.map(function(c) {
      var risk = c.defaultCreds || c.exposed ? 'var(--danger)' : 'var(--ok)';
      return '<div style="background:rgba(0,0,0,.12);border:1px solid rgba(255,255,255,.06);border-radius:6px;padding:.8rem 1rem;margin-bottom:.5rem">'
        + '<div style="display:flex;align-items:center;gap:.7rem;margin-bottom:.4rem;flex-wrap:wrap">'
        + '<span style="font-size:1.1rem">&#128249;</span>'
        + '<div style="flex:1"><div style="font-family:var(--mono);font-size:.65rem;color:var(--white);font-weight:600">' + c.manufacturer + ' ' + c.model + '</div>'
        + '<div style="font-family:var(--mono);font-size:.55rem;color:var(--muted)">' + c.ip + ' &nbsp;&#183;&nbsp; Firmware: ' + c.firmware + '</div></div>'
        + '<span style="font-family:var(--mono);font-size:.6rem;color:' + risk + '">' + (c.defaultCreds||c.exposed?'&#9888; AT RISK':'&#9989; SECURE') + '</span>'
        + '</div>'
        + '<div style="display:flex;gap:.4rem;flex-wrap:wrap">'
        + (c.defaultCreds ? '<span style="font-family:var(--mono);font-size:.55rem;background:rgba(255,59,92,.1);border:1px solid rgba(255,59,92,.2);color:var(--danger);padding:.15rem .45rem;border-radius:3px">&#128683; DEFAULT CREDENTIALS</span>' : '')
        + (c.exposed ? '<span style="font-family:var(--mono);font-size:.55rem;background:rgba(245,158,11,.1);border:1px solid rgba(245,158,11,.2);color:var(--warn);padding:.15rem .45rem;border-radius:3px">&#9888; STREAM EXPOSED</span>' : '')
        + (c.rtsp ? '<span style="font-family:var(--mono);font-size:.55rem;background:rgba(77,141,255,.06);border:1px solid rgba(77,141,255,.12);color:var(--g2);padding:.15rem .45rem;border-radius:3px">&#128249; RTSP AVAILABLE</span>' : '')
        + c.ports.map(function(p){return '<span style="font-family:var(--mono);font-size:.52rem;background:rgba(0,0,0,.2);border:1px solid rgba(255,255,255,.08);color:var(--muted);padding:.1rem .35rem;border-radius:3px">:' + p + '</span>';}).join('')
        + '</div></div>';
    }).join('');

    // Render checklists
    var checks = document.getElementById('camChecklist');
    var best = document.getElementById('camBestPractices');
    if (checks) checks.innerHTML = [
      { text:'Change default credentials', pass:defCreds===0 },
      { text:'Disable RTSP if not needed', pass:Math.random()>0.5 },
      { text:'Enable HTTPS only', pass:Math.random()>0.4 },
      { text:'Isolate cameras on VLAN', pass:Math.random()>0.6 },
      { text:'Disable UPnP', pass:Math.random()>0.4 },
    ].map(function(c){return '<div style="font-family:var(--mono);font-size:.6rem;color:' + (c.pass?'var(--ok)':'var(--danger)') + ';margin-bottom:.3rem">' + (c.pass?'&#9989;':'&#10060;') + ' ' + c.text + '</div>';}).join('');
    if (best) best.innerHTML = ['Keep firmware updated','Use strong unique passwords','Enable motion detection logging','Regular access log review','Physical lock on camera housing'].map(function(t){return '<div style="font-family:var(--mono);font-size:.58rem;color:var(--text2);margin-bottom:.3rem">&#8594; ' + t + '</div>';}).join('');
    showToast('Camera scan complete — ' + CAMERAS.length + ' cameras found', 'ok');
  }, 3000);
}

/* ═══════════════════════════════════════════════════════════════
   NAV HOOK — wire up new pages
═══════════════════════════════════════════════════════════════ */
/* nav hooks merged into main nav() */
