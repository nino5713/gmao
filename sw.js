const CACHE = 'gmao-v209';
const PRECACHE = ['/mobile', '/assets/socom-logo.png', '/icons/socom-icon-192.png', '/icons/socom-icon-512.png', '/icons/socom-apple-touch-icon.png', '/manifest.json'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(PRECACHE)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});

self.addEventListener('fetch', e => {
  if (e.request.url.includes('/api/')) {
    e.respondWith(fetch(e.request).catch(() => new Response(JSON.stringify({error:'Hors ligne'}), {status:503, headers:{'Content-Type':'application/json'}})));
    return;
  }
  e.respondWith(caches.match(e.request).then(r => r || fetch(e.request).then(res => {
    if (res && res.status === 200) { const c = res.clone(); caches.open(CACHE).then(cache => cache.put(e.request, c)); }
    return res;
  }).catch(() => caches.match('/mobile'))));
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
