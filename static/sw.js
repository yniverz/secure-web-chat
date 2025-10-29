// Service worker: cache core assets, store ephemeral private key, and decrypt notification payloads.
const CACHE = 'secure-chat-cache-v2';
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

// ---- Minimal IndexedDB for storing the active decrypted private JWK (ephemeral) ----
const DB_NAME = 'secure-chat';
const DB_STORE = 'keys';

function idbOpen() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = (ev) => {
      const db = req.result;
      if (!db.objectStoreNames.contains(DB_STORE)) db.createObjectStore(DB_STORE);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function idbPut(key, value) {
  const db = await idbOpen();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(DB_STORE, 'readwrite');
    tx.objectStore(DB_STORE).put(value, key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

async function idbGet(key) {
  const db = await idbOpen();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(DB_STORE, 'readonly');
    const req = tx.objectStore(DB_STORE).get(key);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function idbDel(key) {
  const db = await idbOpen();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(DB_STORE, 'readwrite');
    tx.objectStore(DB_STORE).delete(key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

// Store only one active account's private key. Keys:
//  - 'active_id' => id_hash string
//  - 'privJwk:<id_hash>' => JWK object
self.addEventListener('message', (event) => {
  const data = event.data || {};
  (async () => {
    if (data.type === 'storePrivKey' && data.id_hash && data.privJwk) {
      await idbPut('active_id', data.id_hash);
      await idbPut('privJwk:' + data.id_hash, data.privJwk);
    } else if (data.type === 'clearPrivKey') {
      const id = await idbGet('active_id');
      if (id) await idbDel('privJwk:' + id);
      await idbDel('active_id');
    } else if (data.type === 'setContacts' && Array.isArray(data.contacts)) {
      // data.contacts: [{ id_hash, name }]
      for (const c of data.contacts) {
        if (c && c.id_hash) await idbPut('name:' + c.id_hash, c.name || '');
      }
    }
  })();
});

// ---- Crypto helpers (subset) ----
const b64u = {
  d: (s) => {
    const pad = '='.repeat((4 - (s.length % 4)) % 4);
    const str = (s || '').replace(/-/g, '+').replace(/_/g, '/') + pad;
    const raw = atob(str);
    const arr = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) arr[i] = raw.charCodeAt(i);
    return arr.buffer;
  }
};

async function importRSAPrivate(privJwk) {
  const algo = { name: 'RSA-OAEP', hash: 'SHA-256' };
  return crypto.subtle.importKey('jwk', privJwk, algo, true, ['decrypt']);
}

async function hybridDecryptRSAOaepSW(privJwk, pack) {
  const priv = await importRSAPrivate(privJwk);
  const rawAes = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, priv, b64u.d(pack.ek));
  const aesKey = await crypto.subtle.importKey('raw', rawAes, 'AES-GCM', false, ['decrypt']);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(b64u.d(pack.iv)) }, aesKey, b64u.d(pack.ct));
  return JSON.parse(new TextDecoder().decode(pt));
}

async function anyClientVisible() {
  const cl = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
  for (const c of cl) {
    // WindowClient has 'focused' and 'visibilityState' in modern browsers
    if (typeof c.focused === 'boolean' && c.focused) return true;
    if (c.visibilityState && c.visibilityState === 'visible') return true;
  }
  return false;
}

// Push handler: if app visible, ignore; otherwise try to decrypt and show message text.
self.addEventListener('push', (event) => {
  event.waitUntil((async () => {
    try {
      const appVisible = await anyClientVisible();
      // If the app is visible, skip showing a notification
      if (appVisible) return;

      const data = event.data ? event.data.json() : null;
      let title = 'Secure Chat';
      let body = 'You received a message';
      let tag = 'secure-chat-generic';
      let fromId = null;

      if (data && data.kind === 'message' && data.payload) {
        try {
          const activeId = await idbGet('active_id');
          const privJwk = activeId ? await idbGet('privJwk:' + activeId) : null;
          if (privJwk && data.payload.type === 'msg' && data.payload.content) {
            const msgObj = await hybridDecryptRSAOaepSW(privJwk, data.payload.content);
            // msgObj: { id?, text, ts, from }
            body = String(msgObj.text || body);
            fromId = msgObj.from || null;
            // Lookup sender name if we have it
            if (fromId) {
              const nm = await idbGet('name:' + fromId);
              title = nm ? nm : 'New message';
            } else {
              title = 'New message';
            }
            tag = 'secure-chat-msg';
            // If app is visible, forward to page instead of showing notification
            if (await anyClientVisible()) {
              const clients = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
              for (const client of clients) {
                client.postMessage({ type: 'incomingMessage', message: msgObj });
              }
              return; // skip notification
            }
          } else if (privJwk && data.payload.type === 'intro' && data.payload.content) {
            const intro = await hybridDecryptRSAOaepSW(privJwk, data.payload.content);
            title = 'New contact';
            body = (intro.name ? `${intro.name} added you` : 'Contact added you');
            tag = 'secure-chat-intro';
          }
        } catch (e) {
          // fall back to generic if decrypt fails
        }
      }

      await self.registration.showNotification(title, {
        body,
        tag,
        icon: './icons/icon-192.png',
        badge: './icons/icon-192.png'
      });
    } catch (e) {
      await self.registration.showNotification('Secure Chat', { body: 'You received a message', tag: 'secure-chat-generic' });
    }
  })());
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
