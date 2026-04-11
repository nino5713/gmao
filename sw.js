/**
 * SOCOM GMAO — Service Worker v2
 * Gère le cache offline et la synchronisation en arrière-plan
 */

const CACHE_NAME   = 'gmao-v2';
const OFFLINE_PAGE = '/mobile';

// Fichiers à mettre en cache immédiatement
const PRECACHE = [
  '/mobile',
  '/manifest.json',
];

// ── Installation ──────────────────────────────────────────────
self.addEventListener('install', evt => {
  evt.waitUntil(
    caches.open(CACHE_NAME)
      .then(c => c.addAll(PRECACHE))
      .then(() => self.skipWaiting())
  );
});

// ── Activation ────────────────────────────────────────────────
self.addEventListener('activate', evt => {
  evt.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys
        .filter(k => k !== CACHE_NAME)
        .map(k => caches.delete(k))
      )
    ).then(() => self.clients.claim())
  );
});

// ── Fetch Strategy ────────────────────────────────────────────
self.addEventListener('fetch', evt => {
  const url = new URL(evt.request.url);

  // Requêtes API : Network-first avec fallback queue offline
  if (url.pathname.startsWith('/api/')) {
    evt.respondWith(networkFirstAPI(evt.request));
    return;
  }

  // Pages HTML : Network-first avec fallback cache
  if (evt.request.mode === 'navigate') {
    evt.respondWith(
      fetch(evt.request)
        .then(r => {
          const clone = r.clone();
          caches.open(CACHE_NAME).then(c => c.put(evt.request, clone));
          return r;
        })
        .catch(() => caches.match(evt.request).then(r => r || caches.match(OFFLINE_PAGE)))
    );
    return;
  }

  // Assets statiques : Cache-first
  evt.respondWith(
    caches.match(evt.request).then(cached => {
      if (cached) return cached;
      return fetch(evt.request).then(r => {
        const clone = r.clone();
        caches.open(CACHE_NAME).then(c => c.put(evt.request, clone));
        return r;
      });
    })
  );
});

// ── API Network-First ─────────────────────────────────────────
async function networkFirstAPI(request) {
  try {
    const response = await fetch(request.clone());
    // Mettre en cache les GET réussis
    if (request.method === 'GET' && response.ok) {
      const cache = await caches.open(CACHE_NAME);
      cache.put(request, response.clone());
    }
    return response;
  } catch (err) {
    // Offline : retourner le cache pour les GET
    if (request.method === 'GET') {
      const cached = await caches.match(request);
      if (cached) return cached;
    }
    // Pour les mutations (POST/PATCH), mettre en file d'attente
    if (['POST', 'PATCH', 'PUT', 'DELETE'].includes(request.method)) {
      await queueOfflineRequest(request);
      return new Response(JSON.stringify({
        _offline: true,
        message: 'Requête mise en file d\'attente — sera envoyée à la reconnexion'
      }), {
        status: 202,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    return new Response(JSON.stringify({ error: 'Hors ligne' }), {
      status: 503,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

// ── File d'attente offline ────────────────────────────────────
const QUEUE_KEY = 'gmao-offline-queue';

async function queueOfflineRequest(request) {
  const body = await request.text();
  const item = {
    url:     request.url,
    method:  request.method,
    headers: Object.fromEntries(request.headers.entries()),
    body,
    ts:      Date.now()
  };
  // Stocker dans IndexedDB via message aux clients
  const clients = await self.clients.matchAll();
  clients.forEach(client => client.postMessage({ type: 'QUEUE_REQUEST', item }));
}

// ── Background Sync ───────────────────────────────────────────
self.addEventListener('sync', evt => {
  if (evt.tag === 'gmao-sync') {
    evt.waitUntil(replayQueue());
  }
});

async function replayQueue() {
  const clients = await self.clients.matchAll();
  clients.forEach(client => client.postMessage({ type: 'REPLAY_QUEUE' }));
}

// ── Push Notifications ────────────────────────────────────────
self.addEventListener('push', evt => {
  const data = evt.data ? evt.data.json() : {};
  evt.waitUntil(
    self.registration.showNotification(data.title || 'GMAO', {
      body: data.body || '',
      icon: '/icon-192.png',
      badge: '/icon-192.png',
      data: data.url || '/'
    })
  );
});

self.addEventListener('notificationclick', evt => {
  evt.notification.close();
  evt.waitUntil(
    clients.openWindow(evt.notification.data)
  );
});
