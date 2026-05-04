// v218.38 : Service Worker intelligent — Network First pour HTML, Cache First pour assets
// La version est injectée dynamiquement par le serveur lors du fetch.
// Stratégie complète :
//   - HTML/JS/CSS (page principale) : Network First avec timeout 3s, fallback cache
//   - Assets statiques (icônes, manifest) : Cache First avec mise à jour en arrière-plan
//   - API : Network only (jamais cachée)
//   - Vérification périodique de /api/version → notifie l'app si nouvelle version

const CACHE_VERSION = 'gmao-v218.38';
const CACHE_STATIC = 'gmao-static-v218.38';

// Assets qui changent rarement (icônes, manifest, push.js)
const STATIC_ASSETS = [
  '/manifest.json',
  '/icons/socom-icon-192.png',
  '/icons/socom-icon-512.png',
  '/icons/socom-apple-touch-icon.png',
  '/assets/socom-logo.png'
];

// Installation : pré-cache les assets statiques uniquement
self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE_STATIC)
      .then(c => c.addAll(STATIC_ASSETS).catch(() => {}))
      .then(() => self.skipWaiting())
  );
});

// Activation : nettoie les anciens caches + claim immédiat
self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys => Promise.all(
      keys.filter(k => k !== CACHE_VERSION && k !== CACHE_STATIC)
          .map(k => caches.delete(k))
    )).then(() => self.clients.claim())
  );
});

// Fetch : stratégies différenciées selon le type de ressource
self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);

  // 1) API : toujours réseau direct, JAMAIS de cache
  if (url.pathname.startsWith('/api/')) {
    e.respondWith(
      fetch(e.request)
        .catch(() => new Response(JSON.stringify({error:'Hors ligne'}),
                                  {status:503, headers:{'Content-Type':'application/json'}}))
    );
    return;
  }

  // 2) Assets statiques (icônes, images, manifest, polices) : Cache First
  if (url.pathname.startsWith('/icons/') ||
      url.pathname.startsWith('/assets/') ||
      url.pathname === '/manifest.json' ||
      url.pathname.match(/\.(png|jpg|jpeg|gif|svg|woff|woff2|ttf|ico)$/i)) {
    e.respondWith(
      caches.match(e.request).then(cached => {
        if (cached) {
          // Mise à jour en arrière-plan (stale-while-revalidate)
          fetch(e.request).then(res => {
            if (res && res.status === 200) {
              caches.open(CACHE_STATIC).then(c => c.put(e.request, res));
            }
          }).catch(() => {});
          return cached;
        }
        return fetch(e.request).then(res => {
          if (res && res.status === 200) {
            const clone = res.clone();
            caches.open(CACHE_STATIC).then(c => c.put(e.request, clone));
          }
          return res;
        });
      })
    );
    return;
  }

  // 3) HTML / JS / CSS / pages : Network First avec timeout 3s, fallback cache
  e.respondWith(
    Promise.race([
      fetch(e.request).then(res => {
        // Si succès : on met à jour le cache
        if (res && res.status === 200) {
          const clone = res.clone();
          caches.open(CACHE_VERSION).then(c => c.put(e.request, clone));
        }
        return res;
      }),
      new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 3000))
    ]).catch(() => {
      // Réseau lent ou KO → on tente le cache
      return caches.match(e.request).then(r => r || caches.match('/mobile'));
    })
  );
});

// Communication avec le client : message SKIP_WAITING permet de forcer l'activation immédiate
self.addEventListener('message', e => {
  if (e.data && e.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});

// ═══════════════════════════════════════════════════════════════════════
// WEB PUSH — Réception et affichage des notifications
// ═══════════════════════════════════════════════════════════════════════
self.addEventListener('push', event => {
  let data = {};
  try { data = event.data ? event.data.json() : {}; }
  catch (e) { data = { title: 'SOCOM GMAO', body: event.data ? event.data.text() : 'Nouvelle notification' }; }
  const title = data.title || 'SOCOM GMAO';
  const options = {
    body: data.body || '',
    icon: data.icon || '/icons/socom-icon-192.png',
    badge: '/icons/socom-icon-192.png',
    tag: data.tag || 'gmao-notif',
    renotify: true,
    data: { url: data.url || '/' },
    requireInteraction: false
  };
  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener('notificationclick', event => {
  event.notification.close();
  const targetUrl = (event.notification.data && event.notification.data.url) || '/';
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(wins => {
      for (const w of wins) {
        try {
          const u = new URL(w.url);
          if (u.origin === self.location.origin && 'focus' in w) {
            if (w.url !== (self.location.origin + targetUrl)) {
              return w.navigate(targetUrl).then(() => w.focus());
            }
            return w.focus();
          }
        } catch (e) {}
      }
      if (clients.openWindow) return clients.openWindow(targetUrl);
    })
  );
});
