// Service Worker minimal pour la version web — uniquement pour recevoir les push.
// Pas de cache (le web charge toujours depuis le réseau).

self.addEventListener('install', e => { self.skipWaiting(); });
self.addEventListener('activate', e => { e.waitUntil(self.clients.claim()); });

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
