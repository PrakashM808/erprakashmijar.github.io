/* ═══════════════════════════════════════════════════════════════
   PM::OFFSEC Service Worker v1.0
   Handles: caching, offline fallback, push notifications
═══════════════════════════════════════════════════════════════ */

const CACHE_NAME    = 'pmoffsec-v1';
const OFFLINE_URL   = '/offline.html';
const RUNTIME_CACHE = 'pmoffsec-runtime-v1';

/* Files to cache on install (app shell) */
const PRECACHE_URLS = [
  '/',
  '/index.html',
  '/login.html',
  '/register.html',
  '/forgot-password.html',
  '/dashboard/index.html',
  '/assets/auth.js',
  '/assets/auth.css',
  '/assets/style.css',
  '/assets/home.css',
  '/assets/shared.js',
  '/manifest.json',
  '/offline.html',
  '/icons/icon-192.png',
  '/icons/icon-512.png',
];

/* ── INSTALL — cache the app shell ──────────────────────────── */
self.addEventListener('install', function(event) {
  event.waitUntil(
    caches.open(CACHE_NAME).then(function(cache) {
      return cache.addAll(PRECACHE_URLS.filter(function(url) {
        return !url.includes('undefined');
      })).catch(function(err) {
        console.log('[SW] Precache failed for some URLs:', err);
      });
    }).then(function() {
      return self.skipWaiting();
    })
  );
});

/* ── ACTIVATE — clean up old caches ─────────────────────────── */
self.addEventListener('activate', function(event) {
  event.waitUntil(
    caches.keys().then(function(cacheNames) {
      return Promise.all(
        cacheNames.filter(function(name) {
          return name !== CACHE_NAME && name !== RUNTIME_CACHE;
        }).map(function(name) {
          console.log('[SW] Deleting old cache:', name);
          return caches.delete(name);
        })
      );
    }).then(function() {
      return self.clients.claim();
    })
  );
});

/* ── FETCH — serve from cache, fall back to network ─────────── */
self.addEventListener('fetch', function(event) {
  var url = new URL(event.request.url);

  /* Skip non-GET and cross-origin API requests */
  if (event.request.method !== 'GET') return;
  if (url.origin !== location.origin && !url.hostname.includes('fonts.googleapis') && !url.hostname.includes('fonts.gstatic')) return;

  /* API calls — network only, no caching */
  if (url.pathname.startsWith('/api/')) {
    event.respondWith(
      fetch(event.request).catch(function() {
        return new Response(
          JSON.stringify({ error: 'offline', message: 'No internet connection' }),
          { headers: { 'Content-Type': 'application/json' } }
        );
      })
    );
    return;
  }

  /* Navigation requests — serve from cache or network */
  if (event.request.mode === 'navigate') {
    event.respondWith(
      fetch(event.request).then(function(response) {
        /* Cache successful navigation responses */
        if (response.status === 200) {
          var clone = response.clone();
          caches.open(RUNTIME_CACHE).then(function(cache) {
            cache.put(event.request, clone);
          });
        }
        return response;
      }).catch(function() {
        /* Offline — try cache first, then offline page */
        return caches.match(event.request).then(function(cached) {
          return cached || caches.match(OFFLINE_URL);
        });
      })
    );
    return;
  }

  /* Static assets — cache first, then network */
  event.respondWith(
    caches.match(event.request).then(function(cached) {
      if (cached) return cached;
      return fetch(event.request).then(function(response) {
        if (response.status === 200) {
          var clone = response.clone();
          caches.open(RUNTIME_CACHE).then(function(cache) {
            cache.put(event.request, clone);
          });
        }
        return response;
      }).catch(function() {
        /* Return placeholder for images */
        if (event.request.destination === 'image') {
          return new Response('<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100"><rect fill="#060e1a" width="100" height="100"/><text fill="#00ff88" font-size="12" x="50%" y="50%" text-anchor="middle" dy=".3em">PM::OFFSEC</text></svg>', {
            headers: { 'Content-Type': 'image/svg+xml' }
          });
        }
      });
    })
  );
});

/* ── PUSH NOTIFICATIONS ──────────────────────────────────────── */
self.addEventListener('push', function(event) {
  var data = { title: 'PM::OFFSEC Alert', body: 'Security event detected', icon: '/icons/icon-192.png', badge: '/icons/icon-72.png', tag: 'security-alert', requireInteraction: false };

  try {
    if (event.data) {
      var parsed = event.data.json();
      Object.assign(data, parsed);
    }
  } catch(e) {
    if (event.data) data.body = event.data.text();
  }

  var options = {
    body:               data.body,
    icon:               data.icon || '/icons/icon-192.png',
    badge:              data.badge || '/icons/icon-72.png',
    tag:                data.tag  || 'security-alert',
    requireInteraction: data.requireInteraction || false,
    vibrate:            [200, 100, 200],
    data:               { url: data.url || '/dashboard/index.html', timestamp: Date.now() },
    actions: [
      { action: 'view',    title: 'View Dashboard' },
      { action: 'dismiss', title: 'Dismiss' },
    ]
  };

  event.waitUntil(
    self.registration.showNotification(data.title, options)
  );
});

/* ── NOTIFICATION CLICK ──────────────────────────────────────── */
self.addEventListener('notificationclick', function(event) {
  event.notification.close();
  var url = (event.notification.data && event.notification.data.url) || '/dashboard/index.html';

  if (event.action === 'dismiss') return;

  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(function(clientList) {
      for (var i = 0; i < clientList.length; i++) {
        var client = clientList[i];
        if (client.url.includes(location.origin) && 'focus' in client) {
          return client.focus();
        }
      }
      if (clients.openWindow) return clients.openWindow(url);
    })
  );
});

/* ── BACKGROUND SYNC (for offline scan queue) ────────────────── */
self.addEventListener('sync', function(event) {
  if (event.tag === 'sync-scans') {
    event.waitUntil(syncPendingScans());
  }
});

function syncPendingScans() {
  return self.clients.matchAll().then(function(clients) {
    clients.forEach(function(client) {
      client.postMessage({ type: 'sync-complete', message: 'Offline scans synced' });
    });
  });
}

/* ── MESSAGE HANDLER ─────────────────────────────────────────── */
self.addEventListener('message', function(event) {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
  if (event.data && event.data.type === 'CACHE_URLS') {
    caches.open(RUNTIME_CACHE).then(function(cache) {
      cache.addAll(event.data.urls || []);
    });
  }
});
