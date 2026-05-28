/* ═══════════════════════════════════════════════════════════════
   PM::OFFSEC — Internationalization (i18n)
   Languages: English (en), Nepali (ne), Spanish (es)
═══════════════════════════════════════════════════════════════ */

var I18N_LANGS = {
  en: { label: 'English', flag: '🇺🇸', dir: 'ltr' },
  ne: { label: 'नेपाली', flag: '🇳🇵', dir: 'ltr' },
  es: { label: 'Español', flag: '🇪🇸', dir: 'ltr' }
};

var I18N = {

  /* ── NAVIGATION ──────────────────────────────────────────── */
  en: {
    // Header
    api_online:       'API ONLINE',
    api_offline:      'API OFFLINE',
    scan_device:      'SCAN DEVICE',
    logout:           'LOGOUT',
    client_portal:    'CLIENT',
    // Sidebar sections
    nav_main:         'MAIN',
    nav_security:     'SECURITY TOOLS',
    nav_soc:          'SOC PLATFORM',
    nav_siem:         'SIEM',
    nav_physical:     'PHYSICAL SECURITY',
    nav_advanced:     'ADVANCED',
    nav_automation:   'AUTOMATION',
    nav_account:      'ACCOUNT',
    // Sidebar items
    nav_dashboard:    'Dashboard',
    nav_devices:      'Devices',
    nav_scanner:      'Scanner',
    nav_alerts:       'Alerts',
    nav_ai:           'AI Analysis',
    nav_reports:      'Reports',
    nav_webscan:      'Website Scanner',
    nav_osint:        'OSINT & Recon',
    nav_threat:       'Threat Intel',
    nav_incidents:    'Incidents',
    nav_iocs:         'IOC Database',
    nav_mitre:        'MITRE ATT&CK',
    nav_playbooks:    'Playbooks',
    nav_wazuh:        'Wazuh',
    nav_splunk:       'Splunk',
    nav_atm:          'ATM Security',
    nav_vending:      'Vending Machines',
    nav_fleet:        'Device Fleet',
    nav_cameras:      'Cameras',
    nav_pentest:      'Pentest Report',
    nav_phishing:     'Phishing Sim',
    nav_compliance:   'Compliance',
    nav_darkweb:      'Dark Web',
    nav_threatfeed:   'Threat Feed',
    nav_soar:         'SOAR Playbooks',
    nav_billing:      'Billing & Plan',
    nav_settings:     'API Settings',
    nav_profile:      'Profile',
    nav_learn:        'Learning Center',
    nav_admin:        'Admin Panel',
    nav_users:        'Users',
    // Dashboard
    dash_welcome:     'WELCOME BACK',
    dash_active:      'ACTIVE DEVICES',
    dash_issues:      'TOTAL ISSUES',
    dash_score:       'AVG SCORE',
    dash_critical:    'CRITICAL ALERTS',
    dash_scanned:     'SCANNED DEVICES',
    dash_activity:    'RECENT ACTIVITY',
    dash_top_issues:  'TOP ISSUES ACROSS ALL DEVICES',
    dash_view_all:    'VIEW ALL',
    dash_add_device:  '+ ADD DEVICE',
    dash_discover:    'DISCOVER NETWORK',
    // Scan modal
    scan_title:       'SCAN A SERVER',
    scan_local_tab:   'THIS MACHINE',
    scan_remote_tab:  'REMOTE VIA SSH',
    scan_start_local: 'START LOCAL SCAN →',
    scan_start_remote:'SCAN REMOTE DEVICE →',
    // Common
    btn_view_scan:    'VIEW SCAN',
    btn_rescan:       'RE-SCAN',
    btn_remove:       'REMOVE',
    btn_save:         'SAVE',
    btn_cancel:       'CANCEL',
    btn_upgrade:      'UPGRADE',
    btn_close:        'CLOSE',
    // Alerts
    alert_critical:   'Critical',
    alert_high:       'High',
    alert_medium:     'Medium',
    alert_low:        'Low',
    // Settings
    settings_api_url: 'API URL (Railway Backend)',
    settings_api_key: 'API KEY',
    settings_test:    'TEST CONNECTION',
    settings_save:    'SAVE SETTINGS',
    settings_lang:    'LANGUAGE',
    // Trial
    trial_expires:    'Trial expires in',
    trial_days:       'days',
    trial_expired:    'FREE TRIAL EXPIRED',
    trial_upgrade_now:'UPGRADE NOW',
  },

  /* ── NEPALI ──────────────────────────────────────────────── */
  ne: {
    // Header
    api_online:       'API अनलाइन',
    api_offline:      'API अफलाइन',
    scan_device:      'यन्त्र स्क्यान',
    logout:           'लगआउट',
    client_portal:    'ग्राहक',
    // Sidebar sections
    nav_main:         'मुख्य',
    nav_security:     'सुरक्षा उपकरण',
    nav_soc:          'SOC प्लेटफर्म',
    nav_siem:         'SIEM',
    nav_physical:     'भौतिक सुरक्षा',
    nav_advanced:     'उन्नत',
    nav_automation:   'स्वचालन',
    nav_account:      'खाता',
    // Sidebar items
    nav_dashboard:    'ड्यासबोर्ड',
    nav_devices:      'यन्त्रहरू',
    nav_scanner:      'स्क्यानर',
    nav_alerts:       'अलर्टहरू',
    nav_ai:           'AI विश्लेषण',
    nav_reports:      'रिपोर्टहरू',
    nav_webscan:      'वेबसाइट स्क्यानर',
    nav_osint:        'OSINT र खुफिया',
    nav_threat:       'खतरा बुद्धिमत्ता',
    nav_incidents:    'घटनाहरू',
    nav_iocs:         'IOC डेटाबेस',
    nav_mitre:        'MITRE ATT&CK',
    nav_playbooks:    'प्लेबुकहरू',
    nav_wazuh:        'Wazuh',
    nav_splunk:       'Splunk',
    nav_atm:          'ATM सुरक्षा',
    nav_vending:      'भेन्डिङ मेसिन',
    nav_fleet:        'यन्त्र फ्लिट',
    nav_cameras:      'क्यामेराहरू',
    nav_pentest:      'पेनटेस्ट रिपोर्ट',
    nav_phishing:     'फिसिङ सिम',
    nav_compliance:   'अनुपालन',
    nav_darkweb:      'डार्क वेब',
    nav_threatfeed:   'खतरा फिड',
    nav_soar:         'SOAR प्लेबुक',
    nav_billing:      'बिलिङ र योजना',
    nav_settings:     'API सेटिङ',
    nav_profile:      'प्रोफाइल',
    nav_learn:        'सिकाइ केन्द्र',
    nav_admin:        'प्रशासन प्यानल',
    nav_users:        'प्रयोगकर्ताहरू',
    // Dashboard
    dash_welcome:     'स्वागत छ',
    dash_active:      'सक्रिय यन्त्रहरू',
    dash_issues:      'कुल समस्याहरू',
    dash_score:       'औसत स्कोर',
    dash_critical:    'गम्भीर अलर्ट',
    dash_scanned:     'स्क्यान गरिएका यन्त्रहरू',
    dash_activity:    'हालको गतिविधि',
    dash_top_issues:  'सबै यन्त्रहरूमा शीर्ष समस्याहरू',
    dash_view_all:    'सबै हेर्नुहोस्',
    dash_add_device:  '+ यन्त्र थप्नुहोस्',
    dash_discover:    'नेटवर्क पत्ता लगाउनुहोस्',
    // Scan modal
    scan_title:       'सर्भर स्क्यान गर्नुहोस्',
    scan_local_tab:   'यो मेसिन',
    scan_remote_tab:  'SSH मार्फत रिमोट',
    scan_start_local: 'स्थानीय स्क्यान सुरू →',
    scan_start_remote:'रिमोट यन्त्र स्क्यान →',
    // Common
    btn_view_scan:    'स्क्यान हेर्नुहोस्',
    btn_rescan:       'पुनः-स्क्यान',
    btn_remove:       'हटाउनुहोस्',
    btn_save:         'सेभ गर्नुहोस्',
    btn_cancel:       'रद्द गर्नुहोस्',
    btn_upgrade:      'अपग्रेड',
    btn_close:        'बन्द गर्नुहोस्',
    // Alerts
    alert_critical:   'गम्भीर',
    alert_high:       'उच्च',
    alert_medium:     'मध्यम',
    alert_low:        'न्यून',
    // Settings
    settings_api_url: 'API URL (Railway ब्याकएन्ड)',
    settings_api_key: 'API कुञ्जी',
    settings_test:    'जडान परीक्षण',
    settings_save:    'सेटिङ सेभ गर्नुहोस्',
    settings_lang:    'भाषा',
    // Trial
    trial_expires:    'ट्रायल समाप्त हुन्छ',
    trial_days:       'दिनमा',
    trial_expired:    'नि:शुल्क ट्रायल समाप्त',
    trial_upgrade_now:'अहिले अपग्रेड गर्नुहोस्',
  },

  /* ── SPANISH ─────────────────────────────────────────────── */
  es: {
    // Header
    api_online:       'API EN LÍNEA',
    api_offline:      'API SIN CONEXIÓN',
    scan_device:      'ESCANEAR DISPOSITIVO',
    logout:           'CERRAR SESIÓN',
    client_portal:    'CLIENTE',
    // Sidebar sections
    nav_main:         'PRINCIPAL',
    nav_security:     'HERRAMIENTAS DE SEGURIDAD',
    nav_soc:          'PLATAFORMA SOC',
    nav_siem:         'SIEM',
    nav_physical:     'SEGURIDAD FÍSICA',
    nav_advanced:     'AVANZADO',
    nav_automation:   'AUTOMATIZACIÓN',
    nav_account:      'CUENTA',
    // Sidebar items
    nav_dashboard:    'Panel',
    nav_devices:      'Dispositivos',
    nav_scanner:      'Escáner',
    nav_alerts:       'Alertas',
    nav_ai:           'Análisis IA',
    nav_reports:      'Informes',
    nav_webscan:      'Escáner Web',
    nav_osint:        'OSINT e Inteligencia',
    nav_threat:       'Intel de Amenazas',
    nav_incidents:    'Incidentes',
    nav_iocs:         'Base de IOC',
    nav_mitre:        'MITRE ATT&CK',
    nav_playbooks:    'Guías de Respuesta',
    nav_wazuh:        'Wazuh',
    nav_splunk:       'Splunk',
    nav_atm:          'Seguridad ATM',
    nav_vending:      'Máquinas Expendedoras',
    nav_fleet:        'Flota de Dispositivos',
    nav_cameras:      'Cámaras',
    nav_pentest:      'Informe Pentest',
    nav_phishing:     'Simulación Phishing',
    nav_compliance:   'Cumplimiento',
    nav_darkweb:      'Dark Web',
    nav_threatfeed:   'Feed de Amenazas',
    nav_soar:         'Guías SOAR',
    nav_billing:      'Facturación y Plan',
    nav_settings:     'Configuración API',
    nav_profile:      'Perfil',
    nav_learn:        'Centro de Aprendizaje',
    nav_admin:        'Panel Admin',
    nav_users:        'Usuarios',
    // Dashboard
    dash_welcome:     'BIENVENIDO',
    dash_active:      'DISPOSITIVOS ACTIVOS',
    dash_issues:      'PROBLEMAS TOTALES',
    dash_score:       'PUNTUACIÓN MEDIA',
    dash_critical:    'ALERTAS CRÍTICAS',
    dash_scanned:     'DISPOSITIVOS ESCANEADOS',
    dash_activity:    'ACTIVIDAD RECIENTE',
    dash_top_issues:  'PRINCIPALES PROBLEMAS EN TODOS LOS DISPOSITIVOS',
    dash_view_all:    'VER TODO',
    dash_add_device:  '+ AGREGAR DISPOSITIVO',
    dash_discover:    'DESCUBRIR RED',
    // Scan modal
    scan_title:       'ESCANEAR SERVIDOR',
    scan_local_tab:   'ESTA MÁQUINA',
    scan_remote_tab:  'REMOTO VÍA SSH',
    scan_start_local: 'INICIAR ESCANEO LOCAL →',
    scan_start_remote:'ESCANEAR DISPOSITIVO REMOTO →',
    // Common
    btn_view_scan:    'VER ESCANEO',
    btn_rescan:       'RE-ESCANEAR',
    btn_remove:       'ELIMINAR',
    btn_save:         'GUARDAR',
    btn_cancel:       'CANCELAR',
    btn_upgrade:      'MEJORAR PLAN',
    btn_close:        'CERRAR',
    // Alerts
    alert_critical:   'Crítico',
    alert_high:       'Alto',
    alert_medium:     'Medio',
    alert_low:        'Bajo',
    // Settings
    settings_api_url: 'URL API (Backend Railway)',
    settings_api_key: 'CLAVE API',
    settings_test:    'PROBAR CONEXIÓN',
    settings_save:    'GUARDAR CONFIGURACIÓN',
    settings_lang:    'IDIOMA',
    // Trial
    trial_expires:    'El período de prueba expira en',
    trial_days:       'días',
    trial_expired:    'PERÍODO DE PRUEBA EXPIRADO',
    trial_upgrade_now:'MEJORAR AHORA',
  }
};

/* ── i18n Engine ─────────────────────────────────────────────── */
var _currentLang = localStorage.getItem('pm_lang') || 'en';

function t(key) {
  var lang = I18N[_currentLang] || I18N.en;
  return lang[key] || I18N.en[key] || key;
}

function setLanguage(lang) {
  if (!I18N[lang]) return;
  _currentLang = lang;
  localStorage.setItem('pm_lang', lang);
  applyLanguage();
  showToast(I18N_LANGS[lang].flag + ' ' + I18N_LANGS[lang].label, 'ok');
}

function applyLanguage() {
  // Apply to all elements with data-i18n attribute
  document.querySelectorAll('[data-i18n]').forEach(function(el) {
    var key = el.getAttribute('data-i18n');
    var val = t(key);
    if (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA') {
      el.placeholder = val;
    } else if (el.tagName === 'TITLE') {
      document.title = val;
    } else {
      el.textContent = val;
    }
  });

  // Update language picker UI
  var picker = document.getElementById('langPickerBtn');
  if (picker) {
    picker.innerHTML = I18N_LANGS[_currentLang].flag + ' ' +
      I18N_LANGS[_currentLang].label +
      ' <span style="font-size:.55rem;opacity:.6">▾</span>';
  }

  // Apply specific known elements
  var apiBtn = document.getElementById('apiStatusText');
  if (apiBtn) {
    var isOnline = typeof API_ONLINE !== 'undefined' && API_ONLINE;
    apiBtn.textContent = isOnline ? t('api_online') : t('api_offline');
  }
  var scanBtn = document.getElementById('scanBtn');
  if (scanBtn) scanBtn.textContent = t('scan_device');
  var logoutBtn = document.querySelector('.hdr-out');
  if (logoutBtn) logoutBtn.textContent = t('logout');

  // Sidebar section labels
  var sectionMap = {
    'MAIN': 'nav_main', 'SECURITY TOOLS': 'nav_security',
    'SOC PLATFORM': 'nav_soc', 'SIEM': 'nav_siem',
    'PHYSICAL SECURITY': 'nav_physical', 'ADVANCED': 'nav_advanced',
    'AUTOMATION': 'nav_automation', 'ACCOUNT': 'nav_account'
  };
  document.querySelectorAll('.sb-label').forEach(function(el) {
    var text = el.textContent.trim();
    if (sectionMap[text]) el.textContent = t(sectionMap[text]);
  });

  // Sidebar nav items
  var navMap = {
    'Dashboard': 'nav_dashboard', 'Devices': 'nav_devices',
    'Scanner': 'nav_scanner', 'Alerts': 'nav_alerts',
    'AI Analysis': 'nav_ai', 'Reports': 'nav_reports',
    'Website Scanner': 'nav_webscan', 'OSINT & Recon': 'nav_osint',
    'Threat Intel': 'nav_threat', 'Incidents': 'nav_incidents',
    'IOC Database': 'nav_iocs', 'MITRE ATT&CK': 'nav_mitre',
    'Playbooks': 'nav_playbooks', 'Wazuh': 'nav_wazuh',
    'Splunk': 'nav_splunk', 'ATM Security': 'nav_atm',
    'Vending Machines': 'nav_vending', 'Device Fleet': 'nav_fleet',
    'Cameras': 'nav_cameras', 'Pentest Report': 'nav_pentest',
    'Phishing Sim': 'nav_phishing', 'Compliance': 'nav_compliance',
    'Dark Web': 'nav_darkweb', 'Threat Feed': 'nav_threatfeed',
    'SOAR Playbooks': 'nav_soar', 'Billing & Plan': 'nav_billing',
    'API Settings': 'nav_settings', 'Profile': 'nav_profile',
    'Learning Center': 'nav_learn', 'Admin Panel': 'nav_admin',
    'Users': 'nav_users'
  };
  document.querySelectorAll('.sb-item span').forEach(function(el) {
    var text = el.textContent.trim();
    if (navMap[text]) el.textContent = t(navMap[text]);
  });

  // Update html lang attribute
  document.documentElement.lang = _currentLang;
}

function buildLangDropdown() {
  var existing = document.getElementById('langDropdown');
  if (existing) { existing.remove(); return; }

  var dropdown = document.createElement('div');
  dropdown.id = 'langDropdown';
  dropdown.style.cssText = [
    'position:absolute', 'top:calc(100% + 6px)', 'right:0',
    'background:rgba(6,13,26,.98)', 'border:1px solid rgba(0,255,136,.15)',
    'border-radius:8px', 'overflow:hidden', 'z-index:9999',
    'box-shadow:0 8px 32px rgba(0,0,0,.5)', 'min-width:140px'
  ].join(';');

  Object.keys(I18N_LANGS).forEach(function(code) {
    var lang = I18N_LANGS[code];
    var item = document.createElement('div');
    item.style.cssText = [
      'padding:.55rem .9rem', 'cursor:pointer',
      'font-family:var(--mono)', 'font-size:.62rem', 'color:var(--white)',
      'display:flex', 'align-items:center', 'gap:.5rem',
      'transition:background .15s',
      code === _currentLang ? 'background:rgba(0,255,136,.08)' : ''
    ].join(';');
    item.innerHTML = '<span style="font-size:.85rem">' + lang.flag + '</span>'
      + '<span>' + lang.label + '</span>'
      + (code === _currentLang ? '<span style="color:var(--g);margin-left:auto">✓</span>' : '');
    item.onmouseenter = function(){ this.style.background='rgba(0,255,136,.06)'; };
    item.onmouseleave = function(){ this.style.background = code===_currentLang?'rgba(0,255,136,.08)':''; };
    item.onclick = function(e) {
      e.stopPropagation();
      setLanguage(code);
      document.getElementById('langDropdown').remove();
    };
    dropdown.appendChild(item);
  });

  var btn = document.getElementById('langPickerBtn');
  if (btn) {
    btn.parentElement.style.position = 'relative';
    btn.parentElement.appendChild(dropdown);
  }

  // Close on outside click
  setTimeout(function() {
    document.addEventListener('click', function handler(e) {
      var dd = document.getElementById('langDropdown');
      if (dd && !dd.contains(e.target)) {
        dd.remove();
        document.removeEventListener('click', handler);
      }
    });
  }, 10);
}

// Auto-apply on load
document.addEventListener('DOMContentLoaded', function() {
  setTimeout(applyLanguage, 200);
});
