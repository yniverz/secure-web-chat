// Minimal service worker: cache core assets for installability (no behavior changes)
const CACHE = 'secure-chat-cache-v1';
const ASSETS = [
  './',
  './index.html',
  './styles.css',
  './app.js',
  './manifest.webmanifest',
  './icons/icon-192.png',
  './icons/icon-512.png',
];

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then(cache => cache.addAll(ASSETS)));
  self.skipWaiting();
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
  );
  self.clients.claim();
});

self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);
  if (e.request.method === 'GET' && url.origin === location.origin) {
    e.respondWith(caches.match(e.request).then(resp => resp || fetch(e.request)));
  }
});

// Generic push handler: payload is a small JSON with {title, body, tag}
self.addEventListener('push', (event) => {
  try {
    const data = event.data ? event.data.json() : { title: 'Secure Chat', body: 'You received a message', tag: 'secure-chat-generic' };
    const title = data.title || 'Secure Chat';
    const options = {
      body: data.body || 'You received a message',
      tag: data.tag || 'secure-chat-generic',
      icon: './icons/icon-192.png',
      badge: './icons/icon-192.png'
    };
    event.waitUntil(self.registration.showNotification(title, options));
  } catch (e) {
    event.waitUntil(self.registration.showNotification('Secure Chat', { body: 'You received a message', tag: 'secure-chat-generic' }));
  }
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  event.waitUntil(
    (async () => {
      const allClients = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
      for (const client of allClients) {
        if ('focus' in client) { client.focus(); return; }
      }
      if (self.clients.openWindow) {
        await self.clients.openWindow('./');
      }
    })()
  );
});
