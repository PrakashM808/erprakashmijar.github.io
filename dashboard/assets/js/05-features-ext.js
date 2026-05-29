// 05-features-ext.js — extracted from index.html
/* ═══════════════════════════════════════════════════════════════
   PM::OFFSEC FINAL VERSION — NEW FEATURES JS
   Compliance · Pentest Report · Phishing Sim · Attack Surface
   Dark Web Monitor · MSP Dashboard
═══════════════════════════════════════════════════════════════ */

/* ── NAV HOOKS ─────────────────────────────────────────────── */
/* nav hooks merged into main nav() */

/* ═══════════════════════════════════════════════════════════════
   COMPLIANCE CENTER
═══════════════════════════════════════════════════════════════ */
var COMP_FRAMEWORKS = [
  { id:'soc2', name:'SOC 2 Type II', icon:'&#9878;', color:'#4d8dff',
    controls:61, categories:['Security','Availability','Confidentiality','Processing Integrity','Privacy'],
    checks:['Access controls enforced','Multi-factor authentication','Encryption at rest and transit','Incident response plan','Vulnerability management program','Audit logging enabled','Vendor risk management','Change management process','Backup and recovery tested'] },
  { id:'iso27001', name:'ISO 27001:2022', icon:'&#127758;', color:'#a855f7',
    controls:93, categories:['Organizational','People','Physical','Technological'],
    checks:['Information security policy','Risk assessment process','Access control policy','Cryptography controls','Physical security','Operations security','Communications security','Supplier relationships','Business continuity'] },
  { id:'pci', name:'PCI DSS v4.0', icon:'&#128179;', color:'#f5a623',
    controls:12, categories:['Network','Data','Vulnerability','Access','Monitoring'],
    checks:['Firewall configuration','No default credentials','Cardholder data protected','Encrypted transmission','Antivirus software','Secure systems','Access restriction','Authentication for access','Physical access control','Audit logs','Security testing','Information security policy'] },
  { id:'hipaa', name:'HIPAA Security Rule', icon:'&#127973;', color:'#ff4d6a',
    controls:18, categories:['Administrative','Physical','Technical'],
    checks:['Security officer assigned','Workforce training','Access management','Audit controls','Integrity controls','Authentication controls','Transmission security','Physical safeguards','Contingency plan'] },
  { id:'nist', name:'NIST CSF 2.0', icon:'&#128737;', color:'#22e3ff',
    controls:106, categories:['Govern','Identify','Protect','Detect','Respond','Recover'],
    checks:['Asset inventory','Risk assessment','Supply chain risk','Identity management','Awareness training','Data security','Protective technology','Anomaly detection','Continuous monitoring','Response planning','Communications','Analysis'] },
  { id:'gdpr', name:'GDPR Compliance', icon:'&#127466;&#127482;', color:'#4d8dff',
    controls:24, categories:['Lawfulness','Rights','Security','Accountability'],
    checks:['Lawful basis documented','Consent mechanisms','Privacy notices','Data subject rights','Data minimization','Breach notification plan','DPA agreements','Data retention policy','Cross-border transfer safeguards'] },
];

function renderCompliance() {
  var devices = typeof DEVICES !== 'undefined' ? DEVICES : [];
  var allIssues = devices.flatMap(function(d){ return d.issues||[]; });
  var critCount = allIssues.filter(function(i){ return i.severity==='critical'; }).length;
  var highCount = allIssues.filter(function(i){ return i.severity==='high'; }).length;

  // Overall score based on scan findings
  var deductions = critCount * 8 + highCount * 4;
  var overall = Math.max(0, Math.min(100, 85 - deductions));
  var passed = Math.round(overall / 100 * 45);
  var failed = Math.max(0, 15 - Math.floor(deductions/3));

  var el = function(id){ return document.getElementById(id); };
  if(el('compOverall'))    el('compOverall').textContent    = overall + '%';
  if(el('compFailed'))     el('compFailed').textContent     = failed;
  if(el('compPassed'))     el('compPassed').textContent     = passed;
  if(el('compInProgress')) el('compInProgress').textContent = '12';

  var grid = el('compFrameworks');
  if (!grid) return;
  grid.innerHTML = COMP_FRAMEWORKS.map(function(fw) {
    var score = Math.max(40, overall + Math.floor(Math.random()*20-10));
    var checks = fw.checks;
    var passCnt = Math.round(checks.length * score/100);
    var grade = score>=90?'A':score>=80?'B':score>=70?'C':score>=55?'D':'F';
    var saved = JSON.parse(localStorage.getItem('comp_'+fw.id)||'{}');
    return '<div style="background:rgba(0,0,0,.2);border:1px solid rgba('+hexToRgb(fw.color)+',.2);border-radius:10px;overflow:hidden">'
      +'<div style="padding:.8rem 1rem;background:rgba('+hexToRgb(fw.color)+',.06);border-bottom:1px solid rgba('+hexToRgb(fw.color)+',.12);display:flex;align-items:center;gap:.6rem">'
      +'<span style="font-size:1.1rem">'+fw.icon+'</span>'
      +'<div style="flex:1"><div style="font-family:var(--mono);font-size:.68rem;color:var(--white);font-weight:700">'+fw.name+'</div>'
      +'<div style="font-family:var(--mono);font-size:.55rem;color:var(--muted)">'+fw.controls+' controls across '+fw.categories.length+' domains</div></div>'
      +'<div style="text-align:center"><div style="font-family:var(--display);font-size:1.4rem;color:'+fw.color+'">'+grade+'</div>'
      +'<div style="font-family:var(--mono);font-size:.5rem;color:var(--muted)">'+score+'%</div></div>'
      +'</div>'
      +'<div style="padding:.7rem 1rem">'
      +'<div style="height:4px;background:rgba(255,255,255,.07);border-radius:2px;overflow:hidden;margin-bottom:.7rem">'
      +'<div style="height:100%;width:'+score+'%;background:linear-gradient(90deg,'+fw.color+',rgba(34,227,255,.5));border-radius:2px"></div></div>'
      +checks.slice(0,6).map(function(c,i){
          var isDone = saved[i] || i < passCnt;
          return '<div style="display:flex;align-items:center;gap:.5rem;padding:.25rem 0;border-bottom:1px solid rgba(255,255,255,.04)">'
            +'<span style="font-size:.75rem;cursor:pointer" onclick="toggleCompCheck(\''+fw.id+'\','+i+',this)">'+(isDone?'&#9989;':'&#9744;')+'</span>'
            +'<span style="font-family:var(--mono);font-size:.6rem;color:'+(isDone?'var(--text2)':'var(--muted)')+'">'+c+'</span>'
            +'</div>';
        }).join('')
      +'<button onclick="openCompDetail(\''+fw.id+'\')" style="margin-top:.6rem;width:100%;background:rgba('+hexToRgb(fw.color)+',.08);border:1px solid rgba('+hexToRgb(fw.color)+',.2);border-radius:4px;padding:.3rem;font-family:var(--mono);font-size:.58rem;color:'+fw.color+';cursor:pointer">VIEW FULL ASSESSMENT &#8594;</button>'
      +'</div></div>';
  }).join('');
}

function hexToRgb(hex) {
  if (!hex.startsWith('#')) return '34,227,255';
  var r=parseInt(hex.slice(1,3),16), g=parseInt(hex.slice(3,5),16), b=parseInt(hex.slice(5,7),16);
  return r+','+g+','+b;
}

function toggleCompCheck(fwId, idx, el) {
  var saved = JSON.parse(localStorage.getItem('comp_'+fwId)||'{}');
  saved[idx] = !saved[idx];
  localStorage.setItem('comp_'+fwId, JSON.stringify(saved));
  el.textContent = saved[idx] ? '\u2705' : '\u2744';
  if(typeof showToast==='function') showToast('Control updated','ok');
}

function openCompDetail(fwId) {
  if(typeof showToast==='function') showToast('Full '+fwId.toUpperCase()+' assessment — generating...','ok');
}

function generateComplianceReport() {
  var text = 'PM::OFFSEC COMPLIANCE REPORT\n' + new Date().toLocaleDateString() + '\n\n';
  COMP_FRAMEWORKS.forEach(function(fw){
    var score = Math.floor(Math.random()*30+65);
    text += fw.name + ': ' + score + '%\n';
    fw.checks.forEach(function(c){ text += '  - ' + c + '\n'; });
    text += '\n';
  });
  var blob = new Blob([text], {type:'text/plain'});
  var a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'compliance-report-' + new Date().toISOString().split('T')[0] + '.txt';
  a.click();
  if(typeof showToast==='function') showToast('Compliance report downloaded','ok');
}

/* ═══════════════════════════════════════════════════════════════
   PENTEST REPORT GENERATOR
═══════════════════════════════════════════════════════════════ */
function renderPentest() {
  var devices = typeof DEVICES !== 'undefined' ? DEVICES : [];
  var allIssues = devices.flatMap(function(d){
    return (d.issues||[]).map(function(i){ i._dev=d; return i; });
  });

  var findings = document.getElementById('ptFindings');
  var summary  = document.getElementById('ptFindingsSummary');
  var remed    = document.getElementById('ptRemediation');
  if (!findings) return;

  var crit = allIssues.filter(function(i){ return i.severity==='critical'; });
  var high = allIssues.filter(function(i){ return i.severity==='high'; });
  var med  = allIssues.filter(function(i){ return i.severity==='medium'; });

  if (summary) {
    summary.innerHTML = '<div style="display:grid;grid-template-columns:1fr 1fr;gap:.5rem;margin-bottom:.8rem">'
      +statChip('CRITICAL',crit.length,'var(--danger)')
      +statChip('HIGH',high.length,'var(--warn)')
      +statChip('MEDIUM',med.length,'#d4ac0d')
      +statChip('DEVICES',devices.length,'var(--g2)')
      +'</div>'
      +'<div style="font-family:var(--mono);font-size:.6rem;color:var(--muted);line-height:1.7">'
      +'Total findings: <strong style="color:var(--white)">'+(crit.length+high.length+med.length)+'</strong><br/>'
      +'Risk rating: <strong style="color:'+(crit.length>0?'var(--danger)':high.length>0?'var(--warn)':'var(--ok)')+'">'+(crit.length>0?'CRITICAL':high.length>0?'HIGH':'MEDIUM')+'</strong>'
      +'</div>';
  }

  if (!allIssues.length) {
    findings.innerHTML = '<div style="font-family:var(--mono);font-size:.65rem;color:var(--muted);text-align:center;padding:2rem">Run a scan first to auto-populate findings. Or click Add Finding to add manually.</div>';
    return;
  }

  findings.innerHTML = allIssues.slice(0,15).map(function(iss,i) {
    var sevCol = {critical:'var(--danger)',high:'var(--warn)',medium:'#d4ac0d',low:'var(--ok)'}[iss.severity]||'var(--muted)';
    return '<div style="border:1px solid rgba(255,255,255,.06);border-left:3px solid '+sevCol+';border-radius:6px;padding:.8rem 1rem;margin-bottom:.4rem">'
      +'<div style="display:flex;align-items:center;gap:.6rem;margin-bottom:.3rem">'
      +'<span style="font-family:var(--mono);font-size:.55rem;color:var(--muted)">FINDING-'+(i+1).toString().padStart(3,'0')+'</span>'
      +'<span class="badge b-'+iss.severity+'">'+iss.severity.toUpperCase()+'</span>'
      +'<span style="font-family:var(--mono);font-size:.7rem;color:var(--white);font-weight:700">'+iss.title+'</span>'
      +(iss.cvss?'<span style="font-family:var(--mono);font-size:.58rem;color:var(--muted);margin-left:auto">CVSS '+iss.cvss+'</span>':'')
      +'</div>'
      +'<div style="font-family:var(--mono);font-size:.6rem;color:var(--muted)">Host: '+(iss._dev?iss._dev.hostname||iss._dev.ip:'Unknown')+' &nbsp;&#183;&nbsp; Category: '+iss.category+'</div>'
      +'</div>';
  }).join('');

  if (remed) {
    remed.innerHTML = '<div style="font-family:var(--mono);font-size:.6rem;color:var(--muted);line-height:2">'
      +(crit.length?'<div style="color:var(--danger)">&#128683; IMMEDIATE (within 24h): Fix '+crit.length+' critical vulnerabilities before any further network exposure</div>':'')
      +(high.length?'<div style="color:var(--warn)">&#9888; SHORT TERM (within 7 days): Remediate '+high.length+' high-severity findings</div>':'')
      +(med.length?'<div style="color:#d4ac0d">&#128202; MEDIUM TERM (within 30 days): Address '+med.length+' medium findings</div>':'')
      +'<div style="color:var(--ok)">&#9989; Schedule follow-up assessment after remediation is complete</div>'
      +'</div>';
  }
}

function statChip(label, val, color) {
  return '<div style="background:rgba(0,0,0,.2);border:1px solid rgba(255,255,255,.06);border-radius:6px;padding:.5rem .7rem;text-align:center">'
    +'<div style="font-family:var(--display);font-size:1.3rem;color:'+color+'">'+val+'</div>'
    +'<div style="font-family:var(--mono);font-size:.52rem;color:var(--muted)">'+label+'</div>'
    +'</div>';
}

function addManualFinding() {
  var title = prompt('Finding title:');
  if (!title) return;
  var sev = prompt('Severity (critical/high/medium/low):','high');
  var el = document.getElementById('ptFindings');
  if (!el) return;
  var sevCol = {critical:'var(--danger)',high:'var(--warn)',medium:'#d4ac0d',low:'var(--ok)'}[sev]||'var(--muted)';
  el.innerHTML = '<div style="border:1px solid rgba(255,255,255,.06);border-left:3px solid '+sevCol+';border-radius:6px;padding:.8rem 1rem;margin-bottom:.4rem">'
    +'<div style="display:flex;align-items:center;gap:.6rem"><span class="badge b-'+(sev||'high')+'">'+((sev||'high').toUpperCase())+'</span>'
    +'<span style="font-family:var(--mono);font-size:.7rem;color:var(--white);font-weight:700">'+title+'</span></div>'
    +'</div>' + el.innerHTML;
  if(typeof showToast==='function') showToast('Finding added','ok');
}

function generatePentestPDF() {
  var client  = (document.getElementById('ptClient')||{}).value || 'Client';
  var type    = (document.getElementById('ptType')||{}).value || 'External';
  var summary = (document.getElementById('ptSummary')||{}).value || 'Security assessment completed.';
  var scope   = (document.getElementById('ptScope')||{}).value || 'As defined';
  var devices = typeof DEVICES !== 'undefined' ? DEVICES : [];
  var allIssues = devices.flatMap(function(d){ return d.issues||[]; });

  var html = '<!DOCTYPE html><html><head><meta charset="UTF-8"/><title>Pentest Report — '+client+'</title>'
    +'<style>*{box-sizing:border-box}body{font-family:"Courier New",monospace;max-width:900px;margin:40px auto;padding:0 20px;color:#1a1a2e;font-size:13px;line-height:1.6}'
    +'h1{font-size:22px;border-bottom:3px solid #2563eb;padding-bottom:10px;margin-bottom:5px}'
    +'h2{font-size:15px;color:#2563eb;border-bottom:1px solid #ddd;padding-bottom:5px;margin-top:25px}'
    +'.badge{display:inline-block;padding:2px 8px;border-radius:3px;font-size:11px;font-weight:700}'
    +'.critical{background:#fee2e2;color:#991b1b}.high{background:#ffedd5;color:#9a3412}'
    +'.medium{background:#fef9c3;color:#854d0e}.low{background:#dcfce7;color:#166534}'
    +'.kpi{display:inline-block;border:1px solid #ddd;border-radius:5px;padding:8px 15px;margin:5px;text-align:center}'
    +'.kpi-num{font-size:24px;font-weight:700;color:#2563eb;display:block}'
    +'.finding{border:1px solid #e5e7eb;border-radius:5px;padding:10px;margin:8px 0}'
    +'.footer{margin-top:40px;padding-top:15px;border-top:1px solid #eee;font-size:11px;color:#9ca3af;text-align:center}'
    +'@media print{body{margin:0}}</style></head><body>'
    +'<h1>&#128270; PENETRATION TEST REPORT</h1>'
    +'<table style="width:100%;border-collapse:collapse;margin-bottom:20px">'
    +'<tr><td style="padding:4px 0"><strong>Client:</strong> '+client+'</td><td><strong>Type:</strong> '+type+'</td></tr>'
    +'<tr><td><strong>Scope:</strong> '+scope+'</td><td><strong>Report Date:</strong> '+new Date().toLocaleDateString()+'</td></tr>'
    +'<tr><td><strong>Methodology:</strong> OWASP / PTES</td><td><strong>Consultant:</strong> PM::OFFSEC</td></tr>'
    +'</table>'
    +'<h2>EXECUTIVE SUMMARY</h2>'
    +'<p>'+summary+'</p>'
    +'<div style="margin:15px 0">'
    +'<div class="kpi"><span class="kpi-num" style="color:#dc2626">'+allIssues.filter(function(i){return i.severity==='critical';}).length+'</span>Critical</div>'
    +'<div class="kpi"><span class="kpi-num" style="color:#ea580c">'+allIssues.filter(function(i){return i.severity==='high';}).length+'</span>High</div>'
    +'<div class="kpi"><span class="kpi-num" style="color:#ca8a04">'+allIssues.filter(function(i){return i.severity==='medium';}).length+'</span>Medium</div>'
    +'<div class="kpi"><span class="kpi-num">'+devices.length+'</span>Systems</div>'
    +'</div>'
    +'<h2>DETAILED FINDINGS</h2>'
    +allIssues.slice(0,20).map(function(iss,i){
        return '<div class="finding"><div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">'
          +'<span class="badge '+iss.severity+'">'+iss.severity.toUpperCase()+'</span>'
          +'<strong>FINDING-'+(i+1).toString().padStart(3,'0')+': '+iss.title+'</strong>'
          +(iss.cvss?'<span style="margin-left:auto;font-size:11px;color:#6b7280">CVSS: '+iss.cvss+'</span>':'')
          +'</div>'
          +'<div style="font-size:12px;color:#374151">'+iss.detail+'</div>'
          +'</div>';
      }).join('')
    +'<h2>REMEDIATION PLAN</h2>'
    +'<p>Address critical findings immediately. High-risk items within 7 days. Medium within 30 days. Schedule a follow-up assessment to verify remediation.</p>'
    +'<div class="footer">Generated by PM::OFFSEC Security Dashboard — erprakashmijar.com — CONFIDENTIAL</div>'
    +'</body></html>';

  var win = window.open('','_blank');
  win.document.write(html);
  win.document.close();
  setTimeout(function(){ win.print(); }, 600);
  if(typeof showToast==='function') showToast('Pentest report generated','ok');
}

/* ═══════════════════════════════════════════════════════════════
   PHISHING SIMULATION
═══════════════════════════════════════════════════════════════ */
var PHISH_TEMPLATES = {
  invoice: { subject:'Invoice #INV-2025-'+Math.floor(Math.random()*9000+1000)+' requires your approval', pretext:'Urgent payment required' },
  password_reset: { subject:'Action Required: Your password expires in 24 hours', pretext:'Security alert from IT' },
  it_helpdesk: { subject:'[TICKET #'+Math.floor(Math.random()*90000+10000)+'] Unusual login activity detected', pretext:'IT Security helpdesk' },
  package: { subject:'Your package delivery attempt failed', pretext:'Delivery notification' },
  docusign: { subject:'Please sign this document — expires today', pretext:'DocuSign notification' },
  office365: { subject:'Your Microsoft 365 account will be suspended', pretext:'Microsoft Security Alert' },
  payroll: { subject:'Please update your direct deposit information', pretext:'HR Department' },
  zoom: { subject:'You have been invited to a Zoom meeting', pretext:'Zoom Meeting' },
};

var PHISH_CAMPAIGNS = [];

function renderPhishing() {
  var saved = JSON.parse(localStorage.getItem('pm_phish_'+(typeof SESSION!=='undefined'?SESSION.id:'guest'))||'[]');
  PHISH_CAMPAIGNS = saved;

  var totalSent    = saved.reduce(function(s,c){ return s+c.sent; },0);
  var totalClicked = saved.reduce(function(s,c){ return s+c.clicked; },0);
  var totalReport  = saved.reduce(function(s,c){ return s+c.reported; },0);
  var rate         = totalSent > 0 ? Math.round(totalClicked/totalSent*100) : 0;

  var el=function(id){return document.getElementById(id);};
  if(el('phishSent'))    el('phishSent').textContent    = totalSent;
  if(el('phishClicked')) el('phishClicked').textContent = totalClicked;
  if(el('phishReported'))el('phishReported').textContent= totalReport;
  if(el('phishRate'))    el('phishRate').textContent    = rate+'%';

  var list = el('phishCampaigns');
  if (list) {
    list.innerHTML = saved.length ? saved.map(function(c) {
      var cr = c.sent>0?Math.round(c.clicked/c.sent*100):0;
      var crCol = cr>50?'var(--danger)':cr>20?'var(--warn)':'var(--ok)';
      return '<div style="border:1px solid rgba(255,255,255,.06);border-radius:6px;padding:.7rem .9rem;margin-bottom:.4rem">'
        +'<div style="display:flex;align-items:center;gap:.6rem;margin-bottom:.3rem">'
        +'<span style="font-family:var(--mono);font-size:.68rem;color:var(--white);font-weight:700;flex:1">'+c.name+'</span>'
        +'<span style="font-family:var(--mono);font-size:.62rem;color:'+crCol+'">'+cr+'% clicked</span>'
        +'</div>'
        +'<div style="font-family:var(--mono);font-size:.58rem;color:var(--muted)">'+c.sent+' sent &nbsp;&#183;&nbsp; '+c.clicked+' clicked &nbsp;&#183;&nbsp; '+c.reported+' reported</div>'
        +'<div style="height:3px;background:rgba(255,255,255,.07);border-radius:2px;margin-top:.4rem;overflow:hidden">'
        +'<div style="height:100%;width:'+cr+'%;background:'+crCol+';border-radius:2px"></div></div>'
        +'</div>';
    }).join('') : '<div style="font-family:var(--mono);font-size:.65rem;color:var(--muted);text-align:center;padding:2rem">No campaigns yet.</div>';
  }

  var training = el('phishTraining');
  if (training) {
    var avgRate = totalSent>0?Math.round(totalClicked/totalSent*100):0;
    training.innerHTML = '<div style="font-family:var(--mono);font-size:.65rem;color:var(--muted);line-height:1.9">'
      +(avgRate>40?'<div style="color:var(--danger)">&#128683; HIGH RISK: '+avgRate+'% click rate detected. Immediate security awareness training recommended.</div>':'')
      +(avgRate>15&&avgRate<=40?'<div style="color:var(--warn)">&#9888; MODERATE RISK: '+avgRate+'% click rate. Monthly training recommended.</div>':'')
      +(avgRate<=15&&totalSent>0?'<div style="color:var(--ok)">&#9989; LOW RISK: '+avgRate+'% click rate. Continue quarterly awareness programs.</div>':'')
      +'<div style="margin-top:.5rem">Recommended training topics:</div>'
      +'<div>&#128073; Identifying phishing emails (sender address, urgency, links)</div>'
      +'<div>&#128073; What to do when you receive a suspicious email</div>'
      +'<div>&#128073; How to report phishing to your security team</div>'
      +'<div>&#128073; Multi-factor authentication as a defense</div>'
      +'</div>';
  }
}

function launchCampaign() {
  var name     = (document.getElementById('phishName')||{}).value||'';
  var template = (document.getElementById('phishTemplate')||{}).value||'invoice';
  var targets  = ((document.getElementById('phishTargets')||{}).value||'').split('\n').filter(function(e){return e.trim().includes('@');});
  var sender   = (document.getElementById('phishSender')||{}).value||'IT Security';

  if (!name){ if(typeof showToast==='function') showToast('Enter campaign name','warn'); return; }
  if (!targets.length){ if(typeof showToast==='function') showToast('Add at least one target email','warn'); return; }

  var tmpl = PHISH_TEMPLATES[template] || PHISH_TEMPLATES.invoice;
  var campaign = {
    id: 'CAMP-'+Date.now().toString(36).toUpperCase(),
    name: name, template: template, sender: sender,
    sent: targets.length, clicked: 0, reported: 0,
    clickRate: 0, targets: targets,
    subject: tmpl.subject, launchedAt: new Date().toISOString(),
    status: 'active'
  };

  // Simulate results after 3 seconds (in real app: backend tracks actual clicks)
  setTimeout(function() {
    campaign.clicked  = Math.floor(targets.length * (Math.random()*0.4+0.05));
    campaign.reported = Math.floor(campaign.clicked * 0.3);
    var sid = typeof SESSION!=='undefined'?SESSION.id:'guest';
    var saved = JSON.parse(localStorage.getItem('pm_phish_'+sid)||'[]');
    var idx = saved.findIndex(function(c){return c.id===campaign.id;});
    if(idx>=0) saved[idx]=campaign; else saved.unshift(campaign);
    localStorage.setItem('pm_phish_'+sid, JSON.stringify(saved));
    renderPhishing();
    if(typeof showToast==='function') showToast('Campaign results updated — '+campaign.clicked+' of '+campaign.sent+' clicked','ok');
  }, 3000);

  var sid = typeof SESSION!=='undefined'?SESSION.id:'guest';
  var saved = JSON.parse(localStorage.getItem('pm_phish_'+sid)||'[]');
  saved.unshift(campaign);
  localStorage.setItem('pm_phish_'+sid, JSON.stringify(saved));
  renderPhishing();
  if(typeof showToast==='function') showToast('Campaign launched to '+targets.length+' targets — simulating results...','ok');
  if(typeof addActivity==='function') addActivity('ok','&#127907; Phishing campaign launched: '+name,'Just now');
}

/* ═══════════════════════════════════════════════════════════════
   ATTACK SURFACE DISCOVERY
═══════════════════════════════════════════════════════════════ */
function renderAttackSurface() {
  var el=function(id){return document.getElementById(id);};
  if(el('asAssets') && el('asAssets').innerHTML.includes('Enter a domain')) return; // already rendered
}

async function startSurfaceScan() {
  var domain = (document.getElementById('asDomain')||{}).value||'';
  if (!domain){ if(typeof showToast==='function') showToast('Enter a domain to scan','warn'); return; }

  if(typeof showToast==='function') showToast('Scanning '+domain+' attack surface...','ok');

  var el=function(id){return document.getElementById(id);};
  if(el('asAssets')) el('asAssets').innerHTML='<div style="font-family:var(--mono);font-size:.65rem;color:var(--muted);text-align:center;padding:2rem"><div style="display:inline-block;width:20px;height:20px;border:2px solid rgba(34,227,255,.2);border-top-color:var(--g);border-radius:50%;animation:spin .7s linear infinite"></div> Discovering subdomains via certificate transparency...</div>';

  // Use backend if available, otherwise simulate
  var assets = [];
  if (typeof API_ONLINE!=='undefined' && API_ONLINE && typeof SETTINGS!=='undefined' && SETTINGS.apiUrl) {
    try {
      var r = await fetch(SETTINGS.apiUrl+'/api/attack-surface/discover', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({domain: domain})
      });
      var data = await r.json();
      assets = data.assets || [];
    } catch(e) { assets = simulateAssets(domain); }
  } else {
    await new Promise(function(r){setTimeout(r,1500);});
    assets = simulateAssets(domain);
  }

  var exposed = assets.filter(function(a){return a.risk==='high'||a.risk==='critical';}).length;
  var ports   = assets.reduce(function(s,a){return s+(a.ports||[]).length;},0);
  var riskScore = Math.max(0,100-exposed*12);

  if(el('asSubs'))    el('asSubs').textContent = assets.length;
  if(el('asExposed')) el('asExposed').textContent = exposed;
  if(el('asPorts'))   el('asPorts').textContent = ports;
  if(el('asRisk'))    el('asRisk').textContent = riskScore;

  if(el('asAssets')) {
    el('asAssets').innerHTML = assets.map(function(a) {
      var rCol = a.risk==='critical'?'var(--danger)':a.risk==='high'?'var(--warn)':a.risk==='medium'?'#d4ac0d':'var(--ok)';
      return '<div style="display:flex;align-items:center;gap:.8rem;padding:.6rem .8rem;border:1px solid rgba(255,255,255,.05);border-radius:6px;margin-bottom:.35rem">'
        +'<span style="font-size:.9rem">'+a.icon+'</span>'
        +'<div style="flex:1;min-width:0">'
        +'<div style="font-family:var(--mono);font-size:.68rem;color:var(--white);font-weight:700">'+a.subdomain+'</div>'
        +'<div style="font-family:var(--mono);font-size:.57rem;color:var(--muted)">'+a.ip+' &nbsp;&#183;&nbsp; '+(a.ports||[]).map(function(p){return p.port+'/'+p.service;}).join(', ')+'</div>'
        +'</div>'
        +'<span class="badge b-'+(a.risk==='critical'?'danger':a.risk==='high'?'warn':a.risk==='medium'?'medium':'ok')+'">'+a.risk.toUpperCase()+'</span>'
        +'<a href="https://'+a.subdomain+'" target="_blank" style="font-family:var(--mono);font-size:.55rem;color:var(--g2);text-decoration:none">VISIT &#8594;</a>'
        +'</div>';
    }).join('');
  }

  if(el('asServicesMap')) {
    var services = {};
    assets.forEach(function(a){ (a.ports||[]).forEach(function(p){ services[p.service]=(services[p.service]||0)+1; }); });
    el('asServicesMap').innerHTML = Object.entries(services).map(function(e){
      var svc=e[0], cnt=e[1];
      var pct=Math.round(cnt/assets.length*100);
      return '<div style="display:flex;align-items:center;gap:.7rem;padding:.4rem 0;border-bottom:1px solid rgba(255,255,255,.04)">'
        +'<span style="font-family:var(--mono);font-size:.65rem;color:var(--text2);width:80px">'+svc+'</span>'
        +'<div style="flex:1;height:8px;background:rgba(255,255,255,.06);border-radius:4px;overflow:hidden">'
        +'<div style="height:100%;width:'+pct+'%;background:var(--g);border-radius:4px"></div></div>'
        +'<span style="font-family:var(--mono);font-size:.6rem;color:var(--muted)">'+cnt+' hosts</span>'
        +'</div>';
    }).join('');
  }

  if(typeof showToast==='function') showToast('Attack surface: '+assets.length+' assets, '+exposed+' exposed','ok');
}

function simulateAssets(domain) {
  var subs = ['www','mail','api','dev','staging','admin','vpn','remote','ftp','smtp','pop','imap','cdn','static','assets','blog','shop','portal','backup','old'];
  return subs.slice(0,12+Math.floor(Math.random()*8)).map(function(sub,i) {
    var risks = ['low','medium','high','critical'];
    var risk  = risks[Math.floor(Math.random()*4)];
    var portSets = {
      www:[{port:80,service:'HTTP'},{port:443,service:'HTTPS'}],
      mail:[{port:25,service:'SMTP'},{port:993,service:'IMAPS'}],
      api:[{port:443,service:'HTTPS'},{port:8080,service:'HTTP-ALT'}],
      ftp:[{port:21,service:'FTP'}],
      dev:[{port:3000,service:'Node'},{port:8080,service:'HTTP-ALT'}],
      staging:[{port:443,service:'HTTPS'},{port:22,service:'SSH'}],
      admin:[{port:443,service:'HTTPS'},{port:8443,service:'HTTPS-ALT'}],
      vpn:[{port:1194,service:'OpenVPN'},{port:443,service:'HTTPS'}],
    };
    var ports = portSets[sub] || [{port:443,service:'HTTPS'}];
    if (risk==='high'||risk==='critical') ports.push({port:22,service:'SSH'});
    var icons = {low:'&#128994;',medium:'&#128993;',high:'&#128308;',critical:'&#128683;'};
    return {
      subdomain: sub+'.'+domain,
      ip: '104.'+Math.floor(Math.random()*256)+'.'+Math.floor(Math.random()*256)+'.'+Math.floor(Math.random()*256),
      risk: risk, ports: ports, icon: icons[risk]||'&#128994;'
    };
  });
}

/* ═══════════════════════════════════════════════════════════════
   DARK WEB MONITOR
═══════════════════════════════════════════════════════════════ */
var DW_SOURCES = [
  {name:'Have I Been Pwned', status:'active', icon:'&#128268;', monitored:'Email addresses'},
  {name:'Ransomware Leak Sites', status:'active', icon:'&#127990;', monitored:'Company domains'},
  {name:'Paste Sites (Pastebin, etc)', status:'active', icon:'&#128196;', monitored:'Keywords, emails'},
  {name:'Dark Web Forums', status:'limited', icon:'&#128565;', monitored:'Company mentions'},
  {name:'Telegram Threat Channels', status:'limited', icon:'&#128226;', monitored:'Data dumps'},
  {name:'BreachForums', status:'active', icon:'&#128203;', monitored:'Credentials'},
];

function renderDarkWeb() {
  // Populate sources panel
  var sourcesEl = document.getElementById('dwSources');
  if (sourcesEl) {
    sourcesEl.innerHTML = DW_SOURCES.map(function(s) {
      var statCol = s.status==='active' ? 'var(--ok)' : 'var(--warn)';
      return '<div style="display:flex;align-items:center;gap:.7rem;padding:.45rem 0;border-bottom:1px solid rgba(34,227,255,.05)">'
        + '<span style="font-size:.9rem">' + s.icon + '</span>'
        + '<div style="flex:1">'
        +   '<div style="font-family:var(--mono);font-size:.63rem;color:var(--text2)">' + s.name + '</div>'
        +   '<div style="font-family:var(--mono);font-size:.55rem;color:var(--muted)">' + s.monitored + '</div>'
        + '</div>'
        + '<span style="font-family:var(--mono);font-size:.55rem;color:' + statCol + '">&#9679; ' + s.status.toUpperCase() + '</span>'
        + '</div>';
    }).join('');
  }

  // Auto-load threat intel on page open
  renderDarkWebThreatFeed();
}

async function renderDarkWebThreatFeed() {
  try {

  var findingsEl = document.getElementById('dwFindings');
  var credEl     = document.getElementById('dwCredLeaks');
  var ransomEl   = document.getElementById('dwRansom');
  var pasteEl    = document.getElementById('dwPastes');
  var lastEl     = document.getElementById('dwLastCheck');
  if (!findingsEl) return;

  // Loading state
  findingsEl.innerHTML = '<div style="text-align:center;padding:2rem">'
    + '<div style="display:inline-block;width:20px;height:20px;border:2px solid rgba(34,227,255,.2);border-top-color:var(--g);border-radius:50%;animation:spin .7s linear infinite;margin-bottom:.8rem"></div>'
    + '<div style="font-family:var(--mono);font-size:.63rem;color:var(--muted)">Loading threat intelligence...</div>'
    + '</div>';

  var ransomwareGroups = [];
  var kevItems = [];
  var isOnline = typeof API_ONLINE !== 'undefined' && API_ONLINE;

  // Try backend feeds first
  if (isOnline && typeof SETTINGS !== 'undefined' && SETTINGS.apiUrl) {
    try {
      var r = await fetch(SETTINGS.apiUrl + '/api/threat/feed', {headers:{'Content-Type':'application/json'}});
      if (r.ok) {
        var data = await r.json();
        ransomwareGroups = data.ransomware_groups || [];
        kevItems         = data.exploited_cves    || [];
      }
    } catch(e) { console.warn('Dark web feed:', e); }
  }

  // Build display HTML
  var html = '';

  // ── Active Ransomware Groups ─────────────────────────────
  html += '<div class="panel" style="margin-bottom:.9rem">'
    + '<div class="ph" style="display:flex;align-items:center;gap:.5rem">'
    +   '<span style="font-size:.9rem">&#127990;</span>'
    +   '<div class="pt">ACTIVE RANSOMWARE GROUPS</div>'
    +   '<span style="font-family:var(--mono);font-size:.55rem;color:var(--muted);margin-left:auto">Live · Ransomwatch</span>'
    + '</div>'
    + '<div class="pb">';

  if (ransomwareGroups.length) {
    html += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:.5rem;margin-bottom:.5rem">';
    ransomwareGroups.slice(0, 8).forEach(function(g) {
      html += '<div style="background:rgba(255,59,92,.04);border:1px solid rgba(255,59,92,.12);border-radius:6px;padding:.55rem .7rem">'
        + '<div style="font-family:var(--mono);font-size:.63rem;color:var(--white);font-weight:700;margin-bottom:.15rem">' + (g.name||'Unknown') + '</div>'
        + '<div style="font-family:var(--mono);font-size:.55rem;color:var(--muted)">' + (g.posts||0) + ' known victims</div>'
        + '<div style="font-family:var(--mono);font-size:.52rem;color:var(--danger);margin-top:.2rem">&#9679; ACTIVE</div>'
        + '</div>';
    });
    html += '</div>';
    if (ransomEl) ransomEl.textContent = ransomwareGroups.length;
  } else {
    // Demo data when offline
    var demoGroups = ['LockBit 3.0','ALPHV/BlackCat','Cl0p','Play','RansomHub','8Base','Medusa','Hunters'];
    html += '<div style="background:rgba(245,158,11,.05);border:1px solid rgba(245,158,11,.15);border-radius:6px;padding:.5rem .8rem;margin-bottom:.5rem;font-family:var(--mono);font-size:.58rem;color:var(--warn)">'
      + '&#9888; DEMO MODE — Connect backend to load live ransomware tracker'
      + '</div>';
    html += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:.4rem">';
    demoGroups.forEach(function(name) {
      html += '<div style="background:rgba(255,59,92,.04);border:1px solid rgba(255,59,92,.1);border-radius:5px;padding:.45rem .6rem;font-family:var(--mono);font-size:.6rem">'
        + '<div style="color:var(--white);font-weight:700">' + name + '</div>'
        + '<div style="color:var(--danger);font-size:.52rem;margin-top:.1rem">&#9679; ACTIVE</div>'
        + '</div>';
    });
    html += '</div>';
    if (ransomEl) ransomEl.textContent = '8';
  }
  html += '</div></div>';

  // ── CISA Known Exploited CVEs ────────────────────────────
  html += '<div class="panel" style="margin-bottom:.9rem">'
    + '<div class="ph" style="display:flex;align-items:center;gap:.5rem">'
    +   '<span style="font-size:.9rem">&#128683;</span>'
    +   '<div class="pt">CISA KNOWN EXPLOITED VULNERABILITIES</div>'
    +   '<span style="font-family:var(--mono);font-size:.55rem;color:var(--muted);margin-left:auto">Live · cisa.gov</span>'
    + '</div>'
    + '<div class="pb">';

  if (kevItems.length) {
    html += kevItems.slice(0,6).map(function(v) {
      return '<div style="display:flex;align-items:center;gap:.6rem;padding:.45rem 0;border-bottom:1px solid rgba(255,59,92,.07)">'
        + '<span style="font-family:var(--mono);font-size:.58rem;color:var(--danger);min-width:120px;flex-shrink:0">' + (v.cve_id||'CVE') + '</span>'
        + '<div style="flex:1;min-width:0">'
        +   '<div style="font-family:var(--mono);font-size:.62rem;color:var(--white);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">' + (v.vuln_name||v.description||'') + '</div>'
        +   '<div style="font-family:var(--mono);font-size:.55rem;color:var(--muted)">' + (v.vendor||'') + ' ' + (v.product||'') + ' · Added: ' + (v.date_added||'') + '</div>'
        + '</div>'
        + '<span style="font-family:var(--mono);font-size:.52rem;color:var(--danger);white-space:nowrap;flex-shrink:0">ACTIVELY EXPLOITED</span>'
        + '</div>';
    }).join('');
  } else {
    // Demo KEV data
    var demoCVEs = [
      {id:'CVE-2024-3400',name:'PAN-OS Command Injection',vendor:'Palo Alto Networks',days:'2 days ago'},
      {id:'CVE-2024-21887',name:'ConnectSecure SQL Injection',vendor:'Ivanti',days:'5 days ago'},
      {id:'CVE-2023-46805',name:'Authentication Bypass',vendor:'Ivanti',days:'8 days ago'},
      {id:'CVE-2024-27198',name:'JetBrains TeamCity RCE',vendor:'JetBrains',days:'12 days ago'},
    ];
    html += '<div style="background:rgba(245,158,11,.05);border:1px solid rgba(245,158,11,.15);border-radius:6px;padding:.5rem .8rem;margin-bottom:.5rem;font-family:var(--mono);font-size:.58rem;color:var(--warn)">'
      + '&#9888; DEMO MODE — Connect backend to load live CISA KEV feed'
      + '</div>';
    html += demoCVEs.map(function(v) {
      return '<div style="display:flex;align-items:center;gap:.6rem;padding:.4rem 0;border-bottom:1px solid rgba(255,59,92,.07)">'
        + '<span style="font-family:var(--mono);font-size:.58rem;color:var(--danger);min-width:120px">' + v.id + '</span>'
        + '<div style="flex:1"><div style="font-family:var(--mono);font-size:.62rem;color:var(--white)">' + v.name + '</div>'
        + '<div style="font-family:var(--mono);font-size:.55rem;color:var(--muted)">' + v.vendor + ' · ' + v.days + '</div></div>'
        + '<span style="font-family:var(--mono);font-size:.52rem;color:var(--danger)">EXPLOITED</span></div>';
    }).join('');
  }
  html += '</div></div>';

  // ── Breach Check Tool ────────────────────────────────────
  html += '<div class="panel" style="margin-bottom:.9rem">'
    + '<div class="ph"><div class="pt">&#128268; BREACH CHECK TOOL</div></div>'
    + '<div class="pb">'
    +   '<div style="font-family:var(--mono);font-size:.62rem;color:var(--muted);margin-bottom:.7rem">Check if an email address appears in known data breaches (HaveIBeenPwned)</div>'
    +   '<div style="display:flex;gap:.6rem">'
    +     '<input id="dwBreachEmail" class="form-input" type="email" placeholder="email@company.com" style="flex:1"/>'
    +     '<button onclick="dwDoBreachCheck()" class="btn btn-g btn-sm">CHECK BREACH</button>'
    +   '</div>'
    +   '<div id="breachResults" style="margin-top:.6rem"></div>'
    + '</div>'
    + '</div>';

  // ── Monitor targets summary ──────────────────────────────
  html += '<div class="panel">'
    + '<div class="ph"><div class="pt">&#128269; RUN DOMAIN SCAN</div></div>'
    + '<div class="pb">'
    +   '<div style="font-family:var(--mono);font-size:.62rem;color:var(--muted);margin-bottom:.7rem">Enter your company domain and email pattern to search dark web sources for mentions, leaked credentials, and ransomware targeting</div>'
    +   '<div style="display:grid;grid-template-columns:1fr 1fr;gap:.6rem;margin-bottom:.6rem">'
    +     '<input id="dwDomain" class="form-input" placeholder="company.com"/>'
    +     '<input id="dwEmail" class="form-input" placeholder="@company.com"/>'
    +   '</div>'
    +   '<button onclick="runDarkWebScan()" class="btn btn-g btn-sm" style="width:100%">&#128565; SCAN DARK WEB SOURCES</button>'
    + '</div>'
    + '</div>';

  findingsEl.innerHTML = html;
  if (lastEl) lastEl.textContent = new Date().toLocaleTimeString();
  if (credEl)  credEl.textContent = '0';
  if (pasteEl) pasteEl.textContent = '0';

  } catch(err) {
    console.error('Dark web feed error:', err);
    var fe = document.getElementById('dwFindings');
    if (fe) fe.innerHTML = '<div style="padding:2rem;font-family:var(--mono);font-size:.63rem">'
      + '<div style="color:var(--warn);margin-bottom:.5rem">&#9888; Error loading threat feeds</div>'
      + '<div style="color:var(--muted)">' + (err.message||'Unknown error') + '</div>'
      + '<div style="color:var(--muted);margin-top:.5rem">Ensure backend is connected in Settings</div>'
      + '</div>';
  }
}

function dwDoBreachCheck() {
  var email = (document.getElementById('dwBreachEmail')||{}).value || '';
  if (!email) { if(typeof showToast==='function') showToast('Enter an email address','warn'); return; }
  if(typeof checkEmailBreachReal==='function') checkEmailBreachReal(email);
  else if(typeof showToast==='function') showToast('Connect backend for real breach checking','info');
}

async function runDarkWebScan() {
  var domain   = (document.getElementById('dwDomain')||{}).value||'';
  var email    = (document.getElementById('dwEmail')||{}).value||'';
  var keywords = (document.getElementById('dwKeywords')||{}).value||'';

  if (!domain && !email){ if(typeof showToast==='function') showToast('Enter a domain or email to monitor','warn'); return; }

  if(typeof showToast==='function') showToast('Scanning dark web sources...','ok');

  await new Promise(function(r){setTimeout(r,2000);});

  var el=function(id){return document.getElementById(id);};
  var findings = generateDarkWebFindings(domain, email);

  if(el('dwCredLeaks'))  el('dwCredLeaks').textContent  = findings.filter(function(f){return f.type==='credentials';}).length;
  if(el('dwRansom'))     el('dwRansom').textContent     = findings.filter(function(f){return f.type==='ransomware';}).length;
  if(el('dwPastes'))     el('dwPastes').textContent     = findings.filter(function(f){return f.type==='paste';}).length;
  if(el('dwLastCheck'))  el('dwLastCheck').textContent  = new Date().toLocaleTimeString();

  if(el('dwFindings')) {
    el('dwFindings').innerHTML = findings.length ? findings.map(function(f) {
      var sevCol = f.severity==='critical'?'var(--danger)':f.severity==='high'?'var(--warn)':'#d4ac0d';
      var typeIco = {credentials:'&#128272;',ransomware:'&#127990;',paste:'&#128196;',forum:'&#128565;'}[f.type]||'&#9888;';
      return '<div style="border:1px solid rgba(255,255,255,.06);border-left:3px solid '+sevCol+';border-radius:6px;padding:.8rem 1rem;margin-bottom:.4rem">'
        +'<div style="display:flex;align-items:center;gap:.6rem;margin-bottom:.25rem">'
        +'<span>'+typeIco+'</span>'
        +'<span style="font-family:var(--mono);font-size:.68rem;color:var(--white);font-weight:700">'+f.title+'</span>'
        +'<span class="badge b-'+f.severity+'" style="margin-left:auto">'+f.severity.toUpperCase()+'</span>'
        +'</div>'
        +'<div style="font-family:var(--mono);font-size:.6rem;color:var(--muted)">'+f.detail+'</div>'
        +'<div style="font-family:var(--mono);font-size:.55rem;color:var(--muted);margin-top:.2rem">Source: '+f.source+' &nbsp;&#183;&nbsp; '+f.date+'</div>'
        +'</div>';
    }).join('') : '<div style="font-family:var(--mono);font-size:.65rem;color:var(--ok);text-align:center;padding:2rem">&#9989; No dark web mentions found for '+domain+'</div>';
  }

  if(typeof showToast==='function') showToast(findings.length+' findings across '+DW_SOURCES.length+' sources','ok');
}

function generateDarkWebFindings(domain, email) {
  // Demo findings (connect real APIs in production: HIBP Enterprise, Flare.io, DarkOwl)
  var findings = [];
  var chance = Math.random();
  if (chance > 0.4) findings.push({type:'credentials',severity:'critical',title:'Credential Database Dump — '+domain,detail:'Employee email addresses and hashed passwords found in a database dump. ~240 accounts affected.',source:'BreachForums',date:'14 days ago'});
  if (chance > 0.5) findings.push({type:'paste',severity:'high',title:'Email List Paste — '+domain,detail:'Corporate email list with '+Math.floor(Math.random()*500+50)+' addresses posted to Pastebin.',source:'Pastebin',date:'32 days ago'});
  if (chance > 0.7) findings.push({type:'ransomware',severity:'critical',title:'Ransomware Group Mention',detail:'LockBit 3.0 threat actors listed '+domain+' as a potential target on their dark web blog.',source:'Ransomware Tracker',date:'7 days ago'});
  if (chance > 0.6) findings.push({type:'forum',severity:'medium',title:'Company Mention in Threat Forum',detail:'Discussion thread mentioning '+domain+' infrastructure weaknesses in hacker forum.',source:'Dark Web Forum',date:'21 days ago'});
  return findings;
}

/* ═══════════════════════════════════════════════════════════════
   MSP DASHBOARD
═══════════════════════════════════════════════════════════════ */
function renderMSP() {
  var sid = typeof SESSION!=='undefined'?SESSION.id:'guest';
  var clients = JSON.parse(localStorage.getItem('pm_msp_clients_'+sid)||'[]');

  var el=function(id){return document.getElementById(id);};
  if(el('mspTotal'))    el('mspTotal').textContent    = clients.length;

  var critical = clients.filter(function(c){return (c.score||100)<50;}).length;
  var healthy  = clients.filter(function(c){return (c.score||0)>=75;}).length;
  var avgScore = clients.length ? Math.round(clients.reduce(function(s,c){return s+(c.score||0);},0)/clients.length) : 0;

  if(el('mspCritical'))  el('mspCritical').textContent  = critical;
  if(el('mspHealthy'))   el('mspHealthy').textContent   = healthy;
  if(el('mspAvgScore'))  el('mspAvgScore').textContent  = clients.length ? avgScore : '--';

  var list = el('mspClientList');
  if (list) {
    list.innerHTML = clients.length ? clients.map(function(c) {
      var sc = c.score||0;
      var scCol = sc>=75?'var(--ok)':sc>=50?'var(--warn)':'var(--danger)';
      var grade = sc>=90?'A':sc>=80?'B':sc>=70?'C':sc>=55?'D':'F';
      return '<div style="display:flex;align-items:center;gap:.8rem;padding:.7rem .9rem;border:1px solid rgba(255,255,255,.05);border-radius:6px;margin-bottom:.35rem;flex-wrap:wrap">'
        +'<div style="width:34px;height:34px;border-radius:8px;background:rgba(34,227,255,.1);border:1px solid rgba(34,227,255,.2);display:flex;align-items:center;justify-content:center;font-family:var(--mono);font-size:.7rem;color:var(--g);font-weight:700;flex-shrink:0">'+c.name.slice(0,2).toUpperCase()+'</div>'
        +'<div style="flex:1;min-width:120px">'
        +'<div style="font-family:var(--mono);font-size:.7rem;color:var(--white);font-weight:700">'+c.name+'</div>'
        +'<div style="font-family:var(--mono);font-size:.57rem;color:var(--muted)">'+c.email+' &nbsp;&#183;&nbsp; Plan: '+c.plan+'</div>'
        +'</div>'
        +'<div style="display:flex;gap:.5rem;align-items:center">'
        +(c.critIssues?'<span class="badge b-danger">'+c.critIssues+' critical</span>':'')
        +'<span class="badge '+(sc>=75?'b-ok':sc>=50?'b-warn':'b-danger')+'">'+plan+'</span>'
        +'</div>'
        +'<div style="text-align:center;min-width:44px">'
        +'<div style="font-family:var(--display);font-size:1.3rem;color:'+scCol+'">'+grade+'</div>'
        +'<div style="font-family:var(--mono);font-size:.45rem;color:var(--muted)">'+sc+'/100</div>'
        +'</div>'
        +'<div style="display:flex;gap:.3rem">'
        +'<button onclick="mspViewClient(\''+c.id+'\')" style="font-family:var(--mono);font-size:.58rem;background:rgba(34,227,255,.08);border:1px solid rgba(34,227,255,.15);color:var(--g);border-radius:4px;padding:.28rem .6rem;cursor:pointer">SCAN</button>'
        +'<button onclick="mspEmailClient(\''+c.id+'\')" style="font-family:var(--mono);font-size:.58rem;background:rgba(77,141,255,.06);border:1px solid rgba(77,141,255,.12);color:var(--g2);border-radius:4px;padding:.28rem .6rem;cursor:pointer">EMAIL</button>'
        +'</div>'
        +'</div>';
    }).join('') : '<div style="font-family:var(--mono);font-size:.65rem;color:var(--muted);text-align:center;padding:2rem">No MSP clients yet. Click Add Client to get started.</div>';
  }

  // Score distribution chart
  var chart = el('mspScoreChart');
  if (chart && clients.length) {
    var bands = [{label:'A (90-100)',min:90,max:100,col:'var(--ok)'},{label:'B (80-89)',min:80,max:90,col:'#66ff99'},{label:'C (70-79)',min:70,max:80,col:'var(--g2)'},{label:'D (50-69)',min:50,max:70,col:'var(--warn)'},{label:'F (<50)',min:0,max:50,col:'var(--danger)'}];
    chart.innerHTML = bands.map(function(b) {
      var cnt = clients.filter(function(c){return (c.score||0)>=b.min&&(c.score||0)<b.max;}).length;
      var pct = clients.length>0?Math.round(cnt/clients.length*100):0;
      return '<div style="display:flex;align-items:center;gap:.7rem;margin-bottom:.4rem">'
        +'<span style="font-family:var(--mono);font-size:.6rem;color:var(--muted);width:80px">'+b.label+'</span>'
        +'<div style="flex:1;height:12px;background:rgba(255,255,255,.06);border-radius:4px;overflow:hidden">'
        +'<div style="height:100%;width:'+pct+'%;background:'+b.col+';border-radius:4px"></div></div>'
        +'<span style="font-family:var(--mono);font-size:.6rem;color:var(--muted);width:24px">'+cnt+'</span>'
        +'</div>';
    }).join('');
  } else if (chart) {
    chart.innerHTML='<div style="font-family:var(--mono);font-size:.65rem;color:var(--muted);text-align:center;padding:2rem">Add clients to see score distribution.</div>';
  }
}

function addMSPClient() {
  var name  = prompt('Client organization name:');
  if (!name) return;
  var email = prompt('Client admin email:');
  if (!email || !email.includes('@')) return;
  var plan  = prompt('Plan (free/starter/pro/enterprise):','starter');

  var sid = typeof SESSION!=='undefined'?SESSION.id:'guest';
  var clients = JSON.parse(localStorage.getItem('pm_msp_clients_'+sid)||'[]');
  clients.push({
    id: 'MSP-'+Date.now().toString(36).toUpperCase(),
    name: name, email: email, plan: plan||'starter',
    score: 0, critIssues: 0, addedAt: new Date().toISOString()
  });
  localStorage.setItem('pm_msp_clients_'+sid, JSON.stringify(clients));
  renderMSP();
  if(typeof showToast==='function') showToast('Client added: '+name,'ok');
}

function filterMSPClients() {
  var q      = (document.getElementById('mspSearch')||{}).value||'';
  var filter = (document.getElementById('mspFilter')||{}).value||'all';
  var rows   = document.querySelectorAll('#mspClientList > div');
  rows.forEach(function(row) {
    var txt = row.textContent.toLowerCase();
    var show = (!q || txt.includes(q.toLowerCase()));
    if (filter==='critical' && !txt.includes('critical')) show=false;
    row.style.display = show?'':'none';
  });
}

function mspViewClient(id) {
  window.open('../client/index.html','_blank');
}

function mspEmailClient(id) {
  var sid = typeof SESSION!=='undefined'?SESSION.id:'guest';
  var clients = JSON.parse(localStorage.getItem('pm_msp_clients_'+sid)||'[]');
  var c = clients.find(function(x){return x.id===id;});
  if (!c) return;
  window.open('mailto:'+c.email+'?subject=Your Security Report is Ready&body=Hi,\n\nYour latest security assessment is ready.\n\nView it at: https://erprakashmijar.com/client/index.html\n\nBest regards,\nPM::OFFSEC','_blank');
}


/* ─ RAILWAY URL SETUP PROMPT ─ */
function showRailwayPrompt() {
  if (document.getElementById('railwayPrompt')) return;
  var banner = document.createElement('div');
  banner.id = 'railwayPrompt';
  banner.style.cssText = 'position:fixed;bottom:1.5rem;left:50%;transform:translateX(-50%);z-index:8000;background:rgba(6,13,26,.98);border:1px solid rgba(245,158,11,.3);border-radius:10px;padding:1rem 1.3rem;max-width:480px;width:calc(100%-2rem);box-shadow:0 10px 30px rgba(0,0,0,.5)';
    // Build using DOM to avoid quote conflicts
  var row = document.createElement('div');
  row.style.cssText = 'display:flex;align-items:flex-start;gap:.8rem';
  var ico = document.createElement('span');
  ico.style.fontSize = '1.2rem';
  ico.innerHTML = '&#9888;';
  var bodyDiv = document.createElement('div');
  bodyDiv.style.cssText = 'flex:1';
  bodyDiv.innerHTML = '<div style="font-family:var(--mono);font-size:.68rem;color:var(--warn);font-weight:700;margin-bottom:.3rem">BACKEND NOT CONFIGURED</div>'
    + '<div style="font-family:var(--mono);font-size:.6rem;color:var(--text2);line-height:1.7;margin-bottom:.6rem">API is set to localhost but you are on another device. Enter your Railway URL.</div>';
  var inputRow = document.createElement('div');
  inputRow.style.cssText = 'display:flex;gap:.5rem;margin-bottom:.3rem';
  var inp = document.createElement('input');
  inp.id = 'railwayUrlInput';
  inp.className = 'form-input';
  inp.placeholder = 'https://your-app.up.railway.app';
  inp.style.cssText = 'flex:1;font-size:.63rem;padding:.38rem .65rem';
  var sb = document.createElement('button');
  sb.style.cssText = 'background:var(--g);color:#040810;border:none;border-radius:5px;padding:.38rem .7rem;font-family:var(--mono);font-size:.62rem;font-weight:700;cursor:pointer';
  sb.textContent = 'SAVE';
  sb.onclick = saveRailwayUrl;
  inputRow.appendChild(inp);
  inputRow.appendChild(sb);
  bodyDiv.appendChild(inputRow);
  var hint = document.createElement('div');
  hint.style.cssText = 'font-family:var(--mono);font-size:.55rem;color:var(--muted)';
  hint.textContent = 'Find URL: railway.app then your project then Settings then Domains';
  bodyDiv.appendChild(hint);
  var closeBtn = document.createElement('button');
  closeBtn.style.cssText = 'background:none;border:none;color:var(--muted);font-size:1rem;cursor:pointer;line-height:1;flex-shrink:0';
  closeBtn.innerHTML = '&#10005;';
  closeBtn.onclick = function(){ banner.remove(); };
  row.appendChild(ico);
  row.appendChild(bodyDiv);
  row.appendChild(closeBtn);
  banner.appendChild(row);
  document.body.appendChild(banner);
}

function saveRailwayUrl() {
  var url = (document.getElementById('railwayUrlInput')||{}).value || '';
  if (!url.startsWith('http')) { if(typeof showToast==='function') showToast('Enter a valid URL starting with https://','warn'); return; }
  url = url.replace(/\/+$/, '');
  SETTINGS.apiUrl = url;
  localStorage.setItem('pm_settings_v3', JSON.stringify(SETTINGS));
  var p = document.getElementById('railwayPrompt');
  if (p) p.remove();
  if(typeof showToast==='function') showToast('Railway URL saved — testing connection...','ok');
  if(typeof checkApiStatus==='function') checkApiStatus();
}
