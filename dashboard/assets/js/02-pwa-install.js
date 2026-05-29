// 02-pwa-install.js — extracted from index.html
/* ── PWA Service Worker Registration ── */
if ('serviceWorker' in navigator) {
  window.addEventListener('load', function() {
    navigator.serviceWorker.register('/sw.js').then(function(reg) {
      console.log('[PWA] Service worker registered:', reg.scope);
      // Check for updates every 60 seconds
      setInterval(function() { reg.update(); }, 60000);
    }).catch(function(err) {
      console.log('[PWA] Registration failed:', err);
    });
  });
}
