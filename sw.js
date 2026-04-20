const CACHE = 'gmao-v45';
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
