// 07-init-hardening.js — extracted from index.html
/* ═══════════════════════════════════════════════════════════════
   PHASE 1 HARDENING — IP Validation, Disclaimers, Security Fixes
═══════════════════════════════════════════════════════════════ */

/* ── IP Validation — block dangerous targets ─────────────────── */
var BLOCKED_IP_RANGES = [
  /^127\./, /^localhost$/i, /^10\./, /^172\.(1[6-9]|2[0-9]|3[01])\./,
  /^192\.168\./, /^169\.254\./, /^::1$/, /^0\.0\.0\.0$/,
  /^metadata\.google\.internal$/i, /^169\.254\.169\.254$/,
  /^100\.64\./, /^198\.51\.100\./, /^203\.0\.113\./
];

function validateScanTarget(host) {
  if (!host || host.trim().length < 4) {
    return { ok: false, reason: 'Please enter a valid hostname or IP address.' };
  }
  host = host.trim().toLowerCase();
  for (var i = 0; i < BLOCKED_IP_RANGES.length; i++) {
    if (BLOCKED_IP_RANGES[i].test(host)) {
      return { ok: false, reason: 'Scanning internal/private IP ranges is not allowed. Enter a public server IP or hostname.' };
    }
  }
  // Block obviously invalid inputs
  if (host.includes('..') || host.includes('/') || host.includes(';') || host.includes('|')) {
    return { ok: false, reason: 'Invalid hostname format.' };
  }
  return { ok: true };
}

/* ── Scan disclaimer ─────────────────────────────────────────── */
function getScanDisclaimer() {
  return '<div style="background:rgba(245,158,11,.06);border:1px solid rgba(245,158,11,.2);border-radius:6px;padding:.65rem .9rem;margin-bottom:.8rem;display:flex;gap:.5rem;align-items:flex-start">'
    + '<span style="font-size:.85rem;flex-shrink:0">&#9888;</span>'
    + '<div style="font-family:var(--mono);font-size:.58rem;color:var(--text2);line-height:1.7">'
    + '<strong style="color:var(--warn)">RISK INDICATOR SCAN</strong> — These results identify common security misconfigurations and known risk patterns. '
    + 'Findings are indicators, not confirmed exploits. Professional verification is recommended before remediation decisions. '
    + '<span style="color:var(--muted)">PM::OFFSEC is not liable for actions taken based on these results.</span>'
    + '</div></div>';
}

/* ── Patch runRemoteScan to validate IP first ────────────────── */
var _origRunRemoteScan = typeof runRemoteScan === 'function' ? runRemoteScan : null;
window.runRemoteScan = function runRemoteScanPatched() {
  var host = (document.getElementById('remoteHost') || {}).value || '';
  var check = validateScanTarget(host);
  if (!check.ok) {
    if (typeof showToast === 'function') showToast(check.reason, 'warn');
    var errEl = document.getElementById('remoteScanError');
    if (errEl) { errEl.textContent = check.reason; errEl.style.display = 'block'; }
    return;
  }
  if (_origRunRemoteScan) _origRunRemoteScan();
}

/* ── Add disclaimer to scan results ─────────────────────────── */
var _origRenderScanResult = typeof renderScanResult === 'function' ? renderScanResult : null;
window.renderScanResult = function renderScanResultPatched(data) {
  if (_origRenderScanResult) _origRenderScanResult(data);
  // Inject disclaimer after results render
  var panel = document.getElementById('scannerBody');
  if (panel && !panel.querySelector('.scan-disclaimer')) {
    var disc = document.createElement('div');
    disc.className = 'scan-disclaimer';
    disc.innerHTML = getScanDisclaimer();
    panel.insertBefore(disc, panel.firstChild);
  }
}

/* ── Dark web demo label ─────────────────────────────────────── */
var _origRunDarkWebScan = typeof runDarkWebScan === 'function' ? runDarkWebScan : null;
window.runDarkWebScan = async function runDarkWebScanPatched() {
  var isReal = typeof API_ONLINE !== 'undefined' && API_ONLINE && 
               typeof SETTINGS !== 'undefined' && SETTINGS.apiUrl;
  if (!isReal) {
    var findingsEl = document.getElementById('dwFindings');
    if (findingsEl) {
      findingsEl.innerHTML = '<div style="background:rgba(139,92,246,.06);border:1px solid rgba(139,92,246,.2);border-radius:6px;padding:.8rem 1rem;margin-bottom:.8rem;font-family:var(--mono);font-size:.6rem;color:var(--text2);line-height:1.7">'
        + '<strong style="color:#c084fc">&#128737; DEMO MODE</strong> — Dark web monitoring requires a connected backend with HIBP API key configured. '
        + 'Results below are simulated for demonstration. Connect your Railway backend and add HIBP_API_KEY to see real breach data.'
        + '</div>';
    }
  }
  if (_origRunDarkWebScan) await _origRunDarkWebScan();
}

/* ── Compliance score disclaimer ─────────────────────────────── */
var _origRenderCompliance = typeof renderCompliance === 'function' ? renderCompliance : null;
window.renderCompliance = function renderCompliancePatched() {
  if (_origRenderCompliance) _origRenderCompliance();
  var el = document.getElementById('compFrameworks');
  if (el && !el.querySelector('.comp-disclaimer')) {
    var disc = document.createElement('div');
    disc.className = 'comp-disclaimer';
    disc.style.cssText = 'grid-column:1/-1;background:rgba(77,141,255,.04);border:1px solid rgba(77,141,255,.12);border-radius:8px;padding:.8rem 1rem;font-family:var(--mono);font-size:.6rem;color:var(--text2);line-height:1.7;margin-bottom:.5rem';
    disc.innerHTML = '<strong style="color:var(--g2)">&#128203; COMPLIANCE INDICATOR</strong> — These scores are calculated from scan findings and self-assessed controls. '
      + 'They indicate your compliance posture but do not constitute a certified audit. '
      + 'For official certification (SOC 2, ISO 27001, etc.) you need a qualified third-party auditor.';
    el.insertBefore(disc, el.firstChild);
  }
}

/* ── Session security — validate plan server-side ───────────── */
function getSecurePlan() {
  // In production this should be verified by the backend JWT
  // For now, read from session but cap at what's stored in auth
  var session = typeof AUTH !== 'undefined' && AUTH.getSession ? AUTH.getSession() : null;
  if (!session) return 'free';
  var plan = session.plan || 'free';
  // Validate against known plans
  var validPlans = ['free', 'starter', 'pro', 'professional', 'enterprise'];
  return validPlans.includes(plan) ? plan : 'free';
}

/* ── Audit log (localStorage until backend connected) ────────── */
var AUDIT_LOG_KEY = 'pm_audit_log';
function auditLog(action, detail) {
  try {
    var logs = JSON.parse(localStorage.getItem(AUDIT_LOG_KEY) || '[]');
    logs.unshift({
      ts: new Date().toISOString(),
      user: typeof SESSION !== 'undefined' ? (SESSION.email || SESSION.id) : 'unknown',
      action: action,
      detail: detail || '',
      ip: 'client-side'
    });
    // Keep last 500 entries
    localStorage.setItem(AUDIT_LOG_KEY, JSON.stringify(logs.slice(0, 500)));
  } catch(e) {}
}

/* ── Hook scan functions for audit logging ───────────────────── */
var _origRunLocalScan = typeof runLocalScan === 'function' ? runLocalScan : null;
window.runLocalScan = function runLocalScanPatched() {
  auditLog('SCAN_LOCAL', 'Local backend scan initiated');
  if (_origRunLocalScan) _origRunLocalScan();
}

/* ── Patch openScanModal to show authorization reminder ─────── */
var _origOpenScanModal = typeof openScanModal === 'function' ? openScanModal : null;
window.openScanModal = function openScanModalPatched() {
  if (_origOpenScanModal) _origOpenScanModal();
  // Remind user about authorization on remote tab
  setTimeout(function() {
    var remTab = document.querySelector('[onclick*="dtab-remote"]');
    if (remTab && !remTab._authReminderAdded) {
      remTab._authReminderAdded = true;
      remTab.addEventListener('click', function() {
        setTimeout(function() {
          var authBox = document.getElementById('remoteScanAuthReminder');
          if (!authBox) {
            var box = document.createElement('div');
            box.id = 'remoteScanAuthReminder';
            box.style.cssText = 'background:rgba(255,59,92,.06);border:1px solid rgba(255,59,92,.2);border-radius:6px;padding:.6rem .8rem;font-family:var(--mono);font-size:.58rem;color:var(--text2);line-height:1.7;margin-bottom:.7rem';
            box.innerHTML = '&#9878; <strong style="color:var(--danger)">LEGAL REQUIREMENT:</strong> Only scan systems you own or have written authorization to test. Unauthorized scanning is a crime under CFAA (18 U.S.C. § 1030).';
            var remotePanel = document.getElementById('dtab-remote');
            if (remotePanel) remotePanel.insertBefore(box, remotePanel.firstChild);
          }
        }, 100);
      });
    }
  }, 500);
}
