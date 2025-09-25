/* ========================= CONFIG ========================= */
const SERVER_BASE = location.origin.replace(/\/+$/, ''); // change if API is elsewhere
const POLL_MS = 1000;

/* ========================= UTILS ========================= */
const enc = new TextEncoder();
const dec = new TextDecoder();
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const b64u = {
    e: b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
    d: s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)).buffer
};
const hex = buf => Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
function randStr(len) { const a = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; let s = ''; for (let i = 0; i < len; i++) s += a[Math.floor(Math.random() * a.length)]; return s; }
function showToast(msg) { const t = document.getElementById('toast'); t.textContent = msg; t.classList.add('show'); setTimeout(() => t.classList.remove('show'), 1600); }
function initials(name) { return (name || '?').split(/\s+/).map(s => s[0]).slice(0, 2).join('').toUpperCase() }

/* ========================= CRYPTO (WebCrypto) =========================
   id_hash: SHA-256("idv1|" + raw_user_id) -> base64url(16 bytes)
   user_hash: SHA-256("userhv1|" + userId + "|" + username + "|" + password) -> 32-byte key
   Contacts, private key JWK, etc are AES-GCM encrypted with user_hash-derived key.
   Messages: hybrid (AES-GCM payload, AES key wrapped by RSA-OAEP).
======================================================================= */
const SALT_ID = "idv1|";
const SALT_USER = "userhv1|";

async function sha256(data) { return crypto.subtle.digest('SHA-256', typeof data === 'string' ? enc.encode(data) : data); }
async function makeIdHash(rawId) {
    const h = await sha256(SALT_ID + rawId);
    return b64u.e(h.slice(0, 16)); // compact
}
async function makeUserKey(userId, username, password) {
    const h = await sha256(SALT_USER + userId + "|" + username + "|" + password);
    // import raw 32B as AES-GCM key
    return crypto.subtle.importKey('raw', h, 'AES-GCM', false, ['encrypt', 'decrypt']);
}
async function aesEncrypt(key, obj) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const pt = enc.encode(JSON.stringify(obj));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, pt);
    return { iv: b64u.e(iv), ct: b64u.e(ct) };
}
async function aesDecrypt(key, pack) {
    const iv = b64u.d(pack.iv); const ct = b64u.d(pack.ct);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(iv) }, key, ct);
    return JSON.parse(dec.decode(pt));
}
async function genRSA() {
    const kp = await crypto.subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['encrypt', 'decrypt']);
    const pub = await crypto.subtle.exportKey('jwk', kp.publicKey);
    const priv = await crypto.subtle.exportKey('jwk', kp.privateKey);
    return { publicKeyJwk: pub, privateKeyJwk: priv };
}
async function importRSA(pubJwk = null, privJwk = null) {
    const algo = { name: 'RSA-OAEP', hash: 'SHA-256' };
    const pub = pubJwk ? await crypto.subtle.importKey('jwk', pubJwk, algo, true, ['encrypt']) : null;
    const priv = privJwk ? await crypto.subtle.importKey('jwk', privJwk, algo, true, ['decrypt']) : null;
    return { pub, priv };
}
async function hybridEncryptRSAOaep(pubJwk, obj) {
    const { pub } = await importRSA(pubJwk);
    const aesKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const pt = enc.encode(JSON.stringify(obj));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, pt);
    const rawAes = await crypto.subtle.exportKey('raw', aesKey);
    const wrapped = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, pub, rawAes);
    return { ek: b64u.e(wrapped), iv: b64u.e(iv), ct: b64u.e(ct) };
}
async function hybridDecryptRSAOaep(privJwk, pack) {
    if (!privJwk || !privJwk.kty) throw new Error('missing or invalid private JWK');
    const { priv } = await importRSA(null, privJwk);           // now safe: pub not imported
    const rawAes = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, priv, b64u.d(pack.ek));
    const aesKey = await crypto.subtle.importKey('raw', rawAes, 'AES-GCM', false, ['decrypt']);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(b64u.d(pack.iv)) }, aesKey, b64u.d(pack.ct));
    return JSON.parse(new TextDecoder().decode(pt));
}

/* ========================= STORAGE (encrypted) ========================= */
const LS_KEYS = {
    raw_user_id: 'sc.raw_user_id',      // plain (non-secret random id)
    id_hash: 'sc.id_hash',              // server-visible id
    enc_private: 'sc.enc_private',      // AES-GCM by user_key
    enc_public: 'sc.enc_public',        // AES-GCM by user_key (redundant but convenient)
    enc_contacts: 'sc.enc_contacts',    // AES-GCM by user_key
    last_username: 'sc.last_username'
};

async function loadEncrypted(key, slot, fallback) {
    const pack = JSON.parse(localStorage.getItem(slot) || 'null');
    if (!pack) return fallback;
    try { return await aesDecrypt(key, pack); } catch { return fallback; }
}
async function saveEncrypted(key, slot, obj) {
    const pack = await aesEncrypt(key, obj);
    localStorage.setItem(slot, JSON.stringify(pack));
}

/* ========================= SERVER CALLS ========================= */
async function api(path, opts = {}) {
    const res = await fetch(SERVER_BASE + path, { headers: { 'Content-Type': 'application/json' }, ...opts });
    if (!res.ok) throw new Error(await res.text());
    return res.json();
}

/* ========================= APP STATE ========================= */
let me = { userId: null, id_hash: null, username: null, userKey: null, pubJwk: null, privJwk: null };
let contacts = [];  // [{name,id_hash, pubJwk, notifUrl?, notifToken?}]
let messagesByContact = new Map();
let activeContact = null;
let pollAbort = null;

/* ========================= PUSH NOTIFICATIONS (reintroduced minimal) =========================
   Flow:
   1. After login user can click bell button (#notif-setup) to enable notifications.
   2. We fetch server VAPID public key (/push/vapid/public) and subscribe via PushManager.
   3. Subscription JSON + our id_hash are POSTed to /push/subscribe (server stores raw JSON).
   4. Server sends generic notification (no message content) on incoming message.
   Privacy: Notification payload is ONLY a generic string; actual encrypted content still polled.
=============================================================================================== */
const PUSH_LS = {
    subscribed: 'sc.push_subscribed'
};

async function fetchVapidPublicKey() {
    const res = await api('/push/vapid/public');
    return res.public_key; // base64url of uncompressed EC point (starts with 0x04)
}

function b64uToUint8(b64url) {
    const pad = '='.repeat((4 - (b64url.length % 4)) % 4);
    const s = b64url.replace(/-/g, '+').replace(/_/g, '/') + pad;
    const raw = atob(s);
    const arr = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) arr[i] = raw.charCodeAt(i);
    return arr;
}

function notifButton() { return document.getElementById('notif-setup'); }

function updateNotifButtonState() {
    const btn = notifButton();
    if (!btn) return;
    if (!me?.id_hash) { btn.disabled = true; btn.title = 'Login first'; return; }
    if (!('serviceWorker' in navigator) || !('PushManager' in window)) {
        btn.disabled = true; btn.title = 'Push not supported in this browser'; return;
    }
    btn.disabled = false; btn.title = 'Enable notifications';
    if (localStorage.getItem(PUSH_LS.subscribed) === '1') {
        btn.classList.add('hidden');
    } else {
        btn.classList.remove('hidden');
    }
}

async function ensureServiceWorkerReady() {
    if (!('serviceWorker' in navigator)) throw new Error('Service worker unsupported');
    // registration already kicked off at bottom of file
    const reg = await navigator.serviceWorker.getRegistration('./sw.js') || await navigator.serviceWorker.ready;
    return reg;
}

async function subscribePush() {
    const btn = notifButton();
    if (btn) btn.disabled = true;
    try {
        const perm = await Notification.requestPermission();
        if (perm !== 'granted') { showToast('Permission denied'); return; }
        const pubKey = await fetchVapidPublicKey();
        const reg = await ensureServiceWorkerReady();
        let sub = await reg.pushManager.getSubscription();
        if (!sub) {
            sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: b64uToUint8(pubKey) });
        }
        // send to server
        await api('/push/subscribe', { method: 'POST', body: JSON.stringify({ id_hash: me.id_hash, subscription: sub.toJSON() }) });
        localStorage.setItem(PUSH_LS.subscribed, '1');
        showToast('Notifications enabled');
    } catch (e) {
        console.error('Push subscribe failed', e);
        showToast('Enable failed');
    } finally {
        updateNotifButtonState();
    }
}

async function resendExistingSubscriptionIfAny() {
    if (localStorage.getItem(PUSH_LS.subscribed) !== '1') return;
    try {
        const reg = await ensureServiceWorkerReady();
        const sub = await reg.pushManager.getSubscription();
        if (sub && me?.id_hash) {
            await api('/push/subscribe', { method: 'POST', body: JSON.stringify({ id_hash: me.id_hash, subscription: sub.toJSON() }) });
        }
    } catch (e) { /* silent */ }
}

function wireNotifButtonOnce() {
    const btn = notifButton();
    if (!btn || btn._wired) return;
    btn._wired = true;
    btn.addEventListener('click', () => {
        if (!me?.id_hash) { showToast('Login first'); return; }
        subscribePush();
    });
}

function initNotificationsUI() {
    wireNotifButtonOnce();
    updateNotifButtonState();
    // Try to re-associate existing subscription after login
    resendExistingSubscriptionIfAny();
}

/* ========================= VIEW WIRING (same UI as before + extras) ========================= */
const V = {
    login: document.getElementById('view-login'),
    contacts: document.getElementById('view-contacts'),
    chat: document.getElementById('view-chat'),
    list: document.getElementById('contacts-list'),
    search: document.getElementById('contact-search'),
    msgList: document.getElementById('messages'),
    chatTitle: document.getElementById('chat-title'),
};
function show(view) {
    const views = { login: V.login, contacts: V.contacts, chat: V.chat };
    for (const k of Object.keys(views)) {
        const el = views[k];
        // reset transforms on every pass
        el.classList.remove('slide-left', 'slide-right');
        if (k === view) {
            el.classList.remove('hidden');
        } else {
            el.classList.add('hidden');
            if (view === 'chat' && k === 'contacts') el.classList.add('slide-left');
            if (view === 'contacts' && k === 'chat') el.classList.add('slide-right');
        }
    }
}
function renderContacts(list) {
    V.list.innerHTML = '';
    if (!list.length) { V.list.innerHTML = '<div class="center muted" style="padding:24px">No contacts yet</div>'; return; }
    list.forEach(c => {
        const row = document.createElement('div'); row.className = 'contact';
        row.innerHTML = `<div class="avatar">${initials(c.name)}</div>
  <div class="meta">
    <div><div class="name">${c.name}</div><div class="last">${(c._last || '')}</div></div>
    <div style="text-align:right"><div class="muted" style="font-size:12px"></div>${c._unread ? `<div class="badge">${c._unread}</div>` : ''}</div>
  </div>`;
        row.addEventListener('click', () => openChat(c.id_hash));
        V.list.appendChild(row);
    });
}
function renderMessages(contactId) {
    const list = messagesByContact.get(contactId) || [];
    V.msgList.innerHTML = '';
    let lastDay = '';
    list.forEach(m => {
        const d = new Date(m.ts).toDateString();
        if (d !== lastDay) { lastDay = d; const sys = document.createElement('div'); sys.className = 'sys'; sys.textContent = d; V.msgList.appendChild(sys); }
        const row = document.createElement('div'); row.className = 'row ' + (m.from === 'me' ? 'me' : 'them');
        const b = document.createElement('div'); b.className = 'bubble'; b.textContent = m.text;
        row.appendChild(b); V.msgList.appendChild(row);
    });
    if (list.length) { const s = document.createElement('div'); s.className = 'stamp'; s.textContent = new Date(list[list.length - 1].ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }); V.msgList.appendChild(s); }
    V.msgList.scrollTop = V.msgList.scrollHeight;
}

/* ========================= CORE FLOWS ========================= */
// 1) Login flow per spec
document.getElementById('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('login-username').value.trim();
    const password = document.getElementById('login-password').value;
    if (!username || !password) { showToast('Enter credentials'); return; }

    // Ensure we have a raw user id + id_hash reserved
    let rawId = localStorage.getItem(LS_KEYS.raw_user_id);
    if (!rawId) {
        while (true) {
            rawId = crypto.getRandomValues(new Uint32Array(4)).join('-');
            const id_hash = await makeIdHash(rawId);
            const ok = await api('/id/reserve', { method: 'POST', body: JSON.stringify({ id_hash }) });
            if (ok.unique) { localStorage.setItem(LS_KEYS.raw_user_id, rawId); localStorage.setItem(LS_KEYS.id_hash, id_hash); break; }
        }
    } else if (!localStorage.getItem(LS_KEYS.id_hash)) {
        const id_hash = await makeIdHash(rawId);
        await api('/id/reserve', { method: 'POST', body: JSON.stringify({ id_hash }) });
        localStorage.setItem(LS_KEYS.id_hash, id_hash);
    }

    const id_hash = localStorage.getItem(LS_KEYS.id_hash);
    const userKey = await makeUserKey(rawId, username, password);

    // Do we have existing encrypted data that must be unlocked?
    const hadPrivatePack = !!localStorage.getItem(LS_KEYS.enc_private);
    let privJwk = null, pubJwk = null, contactsDecrypted = [];
    let decryptOk = false;

    if (hadPrivatePack) {
        try {
            // Try to decrypt with the provided username/password-derived key
            privJwk = await loadEncrypted(userKey, LS_KEYS.enc_private, null);
            pubJwk = await loadEncrypted(userKey, LS_KEYS.enc_public, null);
            contactsDecrypted = await loadEncrypted(userKey, LS_KEYS.enc_contacts, []);
            decryptOk = !!(privJwk && privJwk.kty && pubJwk && pubJwk.kty);
        } catch { decryptOk = false; }
    }

    // If there was existing data but we couldn't decrypt, ASK first.
    if (hadPrivatePack && !decryptOk) {
        const confirmed = confirm(
            `These credentials do not unlock the local data on this device.\n\nPress “Cancel” to try again, or “OK” to continue with NEW keys (your local contacts here will reset).`
        );
        if (!confirmed) return; // let the user retry

        // Wipe old encrypted blobs we can't read (id_hash stays intact)
        localStorage.removeItem(LS_KEYS.enc_private);
        localStorage.removeItem(LS_KEYS.enc_public);
        localStorage.removeItem(LS_KEYS.enc_contacts);

        // Proceed as a fresh device state
        privJwk = null; pubJwk = null; contactsDecrypted = [];
    }

    // Generate keys if first-time or user chose to proceed fresh
    if (!privJwk || !pubJwk) {
        const kp = await genRSA();
        privJwk = kp.privateKeyJwk;
        pubJwk = kp.publicKeyJwk;
        await saveEncrypted(userKey, LS_KEYS.enc_private, privJwk);
        await saveEncrypted(userKey, LS_KEYS.enc_public, pubJwk);
        await saveEncrypted(userKey, LS_KEYS.enc_contacts, contactsDecrypted); // [] on fresh
        if (hadPrivatePack && !decryptOk) {
            showToast('New device keys created — share your contact again so peers update your key.');
        }
    }

    // Load contacts (already decrypted above if present)
    if (!contactsDecrypted) {
        contactsDecrypted = await loadEncrypted(userKey, LS_KEYS.enc_contacts, []);
    }

    // Commit session state
    me = { userId: rawId, id_hash, username, userKey, pubJwk, privJwk };
    contacts = contactsDecrypted;
    localStorage.setItem(LS_KEYS.last_username, username);

    await startPolling();
    renderContacts(contacts);
    initNotificationsUI();
    show('contacts');
});


// 2) Logout
document.getElementById('logout-btn').addEventListener('click', () => {
    if (pollAbort) { pollAbort.abort(); pollAbort = null; }
    me = { userId: null, id_hash: null, username: null, userKey: null, pubJwk: null, privJwk: null };
    contacts = []; messagesByContact = new Map(); activeContact = null;
    document.getElementById('login-password').value = '';
    show('login');
});

// notifications removed

// 3) Search + Add via 8-char code
V.search.addEventListener('input', async () => {
    const q = V.search.value.trim();
    if (q.length === 8) {
        try {
            const s4 = q.slice(0, 4), k4 = q.slice(4, 8);
            const res = await api(`/share/get/${encodeURIComponent(s4)}`, { method: 'GET' });
            // decrypt blob with k4
            const key = await crypto.subtle.importKey('raw', enc.encode(k4.padEnd(32, 'x')).slice(0, 32), 'AES-GCM', false, ['decrypt']);
            const blob = await aesDecrypt(key, res.blob);
            // blob: { id_hash, pubJwk, name }
            // Add/merge contact (you choose a name locally)
            let c = contacts.find(c => c.id_hash === blob.id_hash);
            if (!c) {
                c = { name: blob.name || blob.id_hash.slice(0, 6), id_hash: blob.id_hash, pubJwk: blob.pubJwk };
                contacts.push(c);
            } else {
                // Merge/refresh info
                c.pubJwk = blob.pubJwk || c.pubJwk;
                c.name = c.name || blob.name || c.id_hash.slice(0, 6);
            }
            await saveEncrypted(me.userKey, LS_KEYS.enc_contacts, contacts);
            renderContacts(contacts);
            showToast('Contact imported!');
            V.search.value = '';
            // Proactively introduce ourselves so the other peer adds us too
            try {
                await sendIntroToPeer(c);
            } catch (e) {
                console.warn('Intro send failed', e);
            }
            // notifications removed: no back card/control message
        } catch (e) { showToast('Invalid 8-char code'); }
    } else {
        // just filter UI
        const L = q ? contacts.filter(c => (c.name || '').toLowerCase().includes(q.toLowerCase())) : contacts;
        renderContacts(L);
    }
});

// 4) Share my contact (create 8-char)
document.getElementById('share-me').addEventListener('click', async () => {
    if (!me?.userKey) { showToast('Log in first'); return; }
    const k4 = randStr(4); // user secret
    const s4 = randStr(4); // ask server to store under this (will retry on conflict server-side)
    const aesKey = await crypto.subtle.importKey('raw', enc.encode(k4.padEnd(32, 'x')).slice(0, 32), 'AES-GCM', false, ['encrypt']);
    const blob = { id_hash: me.id_hash, pubJwk: me.pubJwk, name: me.username };
    const encBlob = await aesEncrypt(aesKey, blob);
    const res = await api('/share/create', { method: 'POST', body: JSON.stringify({ prefer_code4: s4, blob: encBlob, ttl_seconds: 3600 }) });
    const code = res.code4 + k4;
    navigator.clipboard?.writeText(code).catch(() => { });
    alert(`Share this 8-char code:\n\n${code}\n\nIt expires in ~1 hour.`);
});

// 5) Rename contact
document.getElementById('rename-contact').addEventListener('click', async () => {
    if (!activeContact) return;
    const c = contacts.find(x => x.id_hash === activeContact);
    const name = prompt('Contact name', c?.name || '');
    if (name) {
        c.name = name;
        await saveEncrypted(me.userKey, LS_KEYS.enc_contacts, contacts);
        V.chatTitle.textContent = c.name;
        renderContacts(contacts);
    }
});

// 6) Open chat
async function openChat(contactId) {
    activeContact = contactId;
    const c = contacts.find(x => x.id_hash === contactId);
    V.chatTitle.textContent = c?.name || contactId.slice(0, 6);
    if (!messagesByContact.get(contactId)) messagesByContact.set(contactId, []);
    renderMessages(contactId);
    show('chat');
}

// 7) Send message (encrypt with recipient pub key)
document.getElementById('composer-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const text = (document.getElementById('message-input').value || '').trim();
    if (!text || !activeContact) return;
    document.getElementById('message-input').value = '';
    const list = messagesByContact.get(activeContact) || [];
    const msg = { id: crypto.randomUUID(), from: 'me', text, ts: Date.now() };
    list.push(msg); messagesByContact.set(activeContact, list); renderMessages(activeContact);

    const c = contacts.find(x => x.id_hash === activeContact);
    try {
        const pack = await hybridEncryptRSAOaep(c.pubJwk, { text, ts: msg.ts, from: me.id_hash });
        await api('/messages/push', { method: 'POST', body: JSON.stringify({ to_id_hash: c.id_hash, payload: { type: 'msg', content: pack } }) });
        // notifications removed: no external notifier hook
    } catch (err) {
        showToast('Send failed');
    }
});

document.getElementById('back-btn').addEventListener('click', () => {
    activeContact = null;
    show('contacts');
});

// 8) Polling every second
async function startPolling() {
    if (pollAbort) { pollAbort.abort(); }
    pollAbort = new AbortController();
    (async () => {
        while (!pollAbort.signal.aborted) {
            try {
                const res = await api('/messages/poll', { method: 'POST', body: JSON.stringify({ id_hash: me.id_hash, max: 40 }) });
                for (const item of res.items) {
                    if (item.payload?.type === 'msg') {
                        try {
                            const msgObj = await hybridDecryptRSAOaep(me.privJwk, item.payload.content);
                            const fromId = msgObj.from;

                            // ensure there's a contact entry
                            let c = contacts.find(x => x.id_hash === fromId);
                            if (!c) {
                                c = { name: fromId.slice(0, 6), id_hash: fromId, pubJwk: null };
                                contacts.push(c);
                                await saveEncrypted(me.userKey, LS_KEYS.enc_contacts, contacts);
                                renderContacts(contacts);
                            }

                            const arr = messagesByContact.get(fromId) || [];
                            arr.push({ id: item.id, from: 'them', text: msgObj.text, ts: msgObj.ts });
                            messagesByContact.set(fromId, arr);

                            c._last = msgObj.text;
                            if (activeContact !== fromId) {
                                c._unread = (c._unread || 0) + 1;
                                renderContacts(contacts);
                                showToast(`New message from ${c.name}`);
                            } else {
                                renderMessages(fromId);
                            }
                        } catch (e) {
                            console.error('Decrypt failed for incoming message', e, item);
                            showToast('Received a message I could not decrypt.');
                        }
                    } else if (item.payload?.type === 'intro') {
                        try {
                            const intro = await hybridDecryptRSAOaep(me.privJwk, item.payload.content);
                            // intro: { id_hash, name, pubJwk }
                            const fromId = intro.id_hash;
                            if (!fromId) continue;
                            let c = contacts.find(x => x.id_hash === fromId);
                            if (!c) {
                                c = { name: (intro.name || fromId.slice(0, 6)), id_hash: fromId, pubJwk: intro.pubJwk || null };
                                contacts.push(c);
                            } else {
                                // Merge/update
                                c.name = c.name || intro.name || c.name;
                                c.pubJwk = intro.pubJwk || c.pubJwk;
                            }
                            await saveEncrypted(me.userKey, LS_KEYS.enc_contacts, contacts);
                            renderContacts(contacts);
                            showToast(`${c.name} added you`);
                        } catch (e) {
                            console.error('Failed to process intro', e, item);
                        }
                    }
                }
            } catch (e) { /* network hiccup ok */ }
            await sleep(POLL_MS);
        }
    })();
}

/* ========================= Intro handshake ========================= */
async function sendIntroToPeer(contact) {
    if (!contact?.id_hash || !contact?.pubJwk) throw new Error('Contact missing id or pub key');
    if (!me?.id_hash || !me?.pubJwk) throw new Error('Not logged in');
    const content = await hybridEncryptRSAOaep(contact.pubJwk, {
        id_hash: me.id_hash,
        name: me.username,
        pubJwk: me.pubJwk,
        ts: Date.now()
    });
    await api('/messages/push', { method: 'POST', body: JSON.stringify({ to_id_hash: contact.id_hash, payload: { type: 'intro', content } }) });
}

/* ========================= Minimal ChatAppAPI shim (optional) =========================
   If you still want a programmatic API (from your earlier UI), here it is.
============================================================================ */
window.ChatAppAPI = {
    async login(username, password) { document.getElementById('login-username').value = username; document.getElementById('login-password').value = password; document.getElementById('login-form').dispatchEvent(new Event('submit', { cancelable: true })); return { id: 'me', username, displayName: username }; },
    async getContacts() { return contacts; },
    async getMessages(contactId) { return messagesByContact.get(contactId) || []; },
    async sendMessage(contactId, text) { const tmpActive = activeContact; activeContact = contactId; document.getElementById('message-input').value = text; document.getElementById('composer-form').dispatchEvent(new Event('submit', { cancelable: true })); activeContact = tmpActive; return { ok: true }; },
    setContacts(list) { contacts = list; saveEncrypted(me.userKey, LS_KEYS.enc_contacts, contacts); renderContacts(contacts); },
    setMessages(contactId, list) { messagesByContact.set(contactId, list); if (activeContact === contactId) renderMessages(contactId); },
    pushIncomingMessage(contactId, message) { const arr = messagesByContact.get(contactId) || []; arr.push(message); messagesByContact.set(contactId, arr); if (activeContact === contactId) renderMessages(contactId); }
};

/* ---- PWA: register the service worker (no behavior change) ---- */
if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
        navigator.serviceWorker.register('./sw.js').catch(() => {});
        // If user already logged in from a previous session (not persisted here) we'd init, but for now just button state
        setTimeout(updateNotifButtonState, 300);
    });
}
