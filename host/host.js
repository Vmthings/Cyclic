/*
 * Cyclic host runtime. Runs in VmThings' browser tab: keeps the database,
 * answers requests from visitors over WebRTC (PeerJS), and talks to Stripe.
 * Everything browser-specific is passed in (SQL, storage, Peer), so it also runs in Node tests.
 */
import core, { SCHEMA, pollStripe, cron, createOwner } from './core.js';

const enc = new TextEncoder(), dec = new TextDecoder();
export const b64 = u8 => btoa(String.fromCharCode(...new Uint8Array(u8)));
export const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const hex = u8 => [...new Uint8Array(u8)].map(b => b.toString(16).padStart(2, '0')).join('');

/* ---------- host key: proves "this is VmThings' host" ---------- */
const ECDSA = { name: 'ECDSA', namedCurve: 'P-256' }, SIGN = { name: 'ECDSA', hash: 'SHA-256' };

export async function generateHostKey() {
  const pair = await crypto.subtle.generateKey(ECDSA, true, ['sign', 'verify']);
  const priv = await crypto.subtle.exportKey('jwk', pair.privateKey), pub = await crypto.subtle.exportKey('jwk', pair.publicKey);
  return { privateJwk: priv, publicJwk: { kty: pub.kty, crv: pub.crv, x: pub.x, y: pub.y } };
}
export const publicOf = jwk => ({ kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y });
export const sameKey = (a, b) => !!a && !!b && a.x === b.x && a.y === b.y;

export async function hostPeerId(publicJwk) {
  const d = await crypto.subtle.digest('SHA-256', enc.encode(publicJwk.x + '.' + publicJwk.y));
  return 'cyclic-' + hex(d).slice(0, 24);
}
async function pwKey(password, salt) {
  const k = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 200000 }, k, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
// Secrets (the host key, the Stripe key) are only ever stored encrypted with the host password.
export async function lock(obj, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
  const data = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await pwKey(password, salt), enc.encode(JSON.stringify(obj)));
  return { salt: b64(salt), iv: b64(iv), data: b64(data) };
}
export async function unlock(blob, password) {
  try {
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(blob.iv) }, await pwKey(password, unb64(blob.salt)), unb64(blob.data));
    return JSON.parse(dec.decode(plain));
  } catch { throw new Error('Wrong password.'); }
}
export async function signHello(privateJwk, nonce) {
  const key = await crypto.subtle.importKey('jwk', privateJwk, ECDSA, false, ['sign']);
  return b64(await crypto.subtle.sign(SIGN, key, enc.encode('cyclic-hello:' + nonce)));
}
export async function verifyHello(publicJwk, nonce, sig) {
  try {
    const key = await crypto.subtle.importKey('jwk', publicOf(publicJwk), ECDSA, false, ['verify']);
    return await crypto.subtle.verify(SIGN, key, unb64(sig), enc.encode('cyclic-hello:' + nonce));
  } catch { return false; }
}

/* ---------- database: SQLite (sql.js) with a D1-style interface ---------- */
export function openDb(SQL, bytes, save) {
  const db = bytes ? new SQL.Database(bytes) : new SQL.Database();
  let inBatch = false, timer = null, saving = Promise.resolve();
  const flush = () => { clearTimeout(timer); timer = null; const data = db.export(); saving = saving.then(() => save(data)).catch(e => console.error('Saving the database failed:', e)); return saving; };
  const changed = () => { if (!inBatch && !timer) timer = setTimeout(flush, 250); };
  const rows = (sql, args) => { const st = db.prepare(sql); try { st.bind(args); const out = []; while (st.step()) out.push(st.getAsObject()); return out; } finally { st.free(); } };
  const prepare = sql => {
    let args = [];
    const st = {
      bind(...a) { args = a; return st; },
      async first() { return rows(sql, args)[0] ?? null; },
      async all() { return { results: rows(sql, args) }; },
      async run() { return st._run(); },
      _run() { db.run(sql, args); const meta = { changes: db.getRowsModified() }; changed(); return { meta }; }
    };
    return st;
  };
  const batch = async list => {                      // one transaction, like D1
    inBatch = true; db.run('BEGIN');
    try { const out = list.map(s => s._run()); db.run('COMMIT'); inBatch = false; changed(); return out; }
    catch (e) { try { db.run('ROLLBACK'); } catch { /* already rolled back */ } inBatch = false; throw e; }
  };
  db.run(SCHEMA);
  return { DB: { prepare, batch }, flush, exportBytes: () => db.export(), close() { flush(); } };
}

/* ---------- running the host ---------- */
const DEFAULTS = {
  CREDIT_CENTS: '10', FEE_PERCENT: '0', HOLD_DAYS: '7', MIN_PAYOUT_CENTS: '500', PLAN_MIN_CENTS: '500',
  BONUS_STANDARD_PERCENT: '5',      // perk: extra credits on each Cyclic Monthly payment (paid for by the host; set 0 to turn off)
  BONUS_ENTERPRISE_PERCENT: '10',   // perk: extra credits on each Enterprise payment (paid for by the host; set 0 to turn off)
  ENTERPRISE_FEE_CENTS: '1000'      // the flat $10 per Enterprise team that goes to the host
};

export function makeRequest(method, path, body, token) {
  if (!['GET', 'POST', 'DELETE'].includes(method) || typeof path !== 'string' || !path.startsWith('/') || path.startsWith('//')) throw new Error('Bad request');
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers.Authorization = 'Bearer ' + String(token);
  return new Request('https://host.local' + path, { method, headers, body: method === 'GET' || method === 'DELETE' ? undefined : JSON.stringify(body ?? {}) });
}

export async function startHost({ SQL, storage, Peer, privateJwk, publicJwk, stripeKey, siteUrl, peerOptions = {}, onStatus = () => {}, timers = true }) {
  const stored = await storage.get('db');
  const handle = openDb(SQL, stored || null, bytes => storage.set('db', bytes));
  const env = { ...DEFAULTS, DB: handle.DB, STRIPE_SECRET_KEY: stripeKey || '', SITE_URL: siteUrl };
  let secret = (await handle.DB.prepare('SELECT v FROM kv WHERE k=?').bind('auth_secret').first())?.v;
  if (!secret) { secret = hex(crypto.getRandomValues(new Uint8Array(32))); await handle.DB.prepare('INSERT INTO kv(k,v) VALUES(?,?)').bind('auth_secret', secret).run(); }
  env.AUTH_SECRET = secret;

  const status = { state: 'starting', clients: 0, lastPoll: null, lastError: null, processed: 0 };
  const push = patch => { Object.assign(status, patch); onStatus({ ...status }); };

  const call = async (method, path, body, token) => {
    const r = await core.fetch(makeRequest(method, path, body, token), env);
    return { status: r.status, data: await r.json().catch(() => ({})) };
  };

  const peerId = await hostPeerId(publicJwk);
  const peer = new Peer(peerId, peerOptions);
  const conns = new Set();
  peer.on('open', () => push({ state: 'online', peerId }));
  peer.on('disconnected', () => { push({ state: 'reconnecting' }); try { peer.reconnect(); } catch { /* retry on the next tick */ } });
  peer.on('error', e => push(e.type === 'unavailable-id'
    ? { state: 'error', lastError: 'Another tab or device is already hosting. Close it first.' }
    : { lastError: e.message || String(e.type) }));
  peer.on('connection', conn => {
    if (conns.size >= 60) { conn.close(); return; }
    conns.add(conn); push({ clients: conns.size });
    const hits = [];
    conn.on('close', () => { conns.delete(conn); push({ clients: conns.size }); });
    conn.on('error', () => { conns.delete(conn); push({ clients: conns.size }); });
    conn.on('data', async msg => {
      try {
        if (!msg || typeof msg !== 'object') return;
        if (msg.t === 'hello' && typeof msg.nonce === 'string' && msg.nonce.length < 100)
          return conn.send({ t: 'hello', sig: await signHello(privateJwk, msg.nonce) });
        if (msg.t !== 'req') return;
        const now = Date.now(); while (hits.length && now - hits[0] > 10000) hits.shift();
        if (hits.push(now) > 30) return conn.send({ t: 'res', id: msg.id, status: 429, data: { error: 'Slow down a little.' } });
        let out;
        try { out = await call(msg.method, msg.path, msg.body, msg.auth); }
        catch (e) { out = { status: 400, data: { error: e.message } }; }
        conn.send({ t: 'res', id: msg.id, status: out.status, data: out.data });
      } catch (e) { console.error(e); }
    });
  });

  const stripePoll = async () => {
    try { const r = await pollStripe(env); push({ lastPoll: Date.now(), processed: status.processed + r.processed, lastError: null }); return r; }
    catch (e) { push({ lastError: 'Stripe: ' + e.message }); return { processed: 0 }; }
  };
  const hourly = async () => { try { await cron(env); } catch (e) { push({ lastError: e.message }); } };
  const ids = [];
  if (timers) {
    setTimeout(stripePoll, 2000); setTimeout(hourly, 10000);
    ids.push(setInterval(stripePoll, 60000), setInterval(hourly, 3600000));
  }

  return {
    call, env, status, peerId, stripePoll, hourly,
    exportDb: () => { handle.flush(); return handle.exportBytes(); },
    flush: () => handle.flush(),
    createOwner: opts => createOwner(env, opts),
    stop() { ids.forEach(clearInterval); conns.forEach(c => { try { c.close(); } catch { /* closed */ } }); try { peer.destroy(); } catch { /* destroyed */ } handle.flush(); push({ state: 'stopped', clients: 0 }); }
  };
}

/* ---------- browser storage (IndexedDB), for the real site ---------- */
export function idbStorage(name = 'cyclic-host') {
  const open = () => new Promise((res, rej) => { const r = indexedDB.open(name, 1); r.onupgradeneeded = () => r.result.createObjectStore('kv'); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); });
  const run = (mode, fn) => open().then(db => new Promise((res, rej) => { const t = db.transaction('kv', mode), q = fn(t.objectStore('kv')); t.oncomplete = () => res(q.result); t.onerror = () => rej(t.error); }));
  return { get: k => run('readonly', s => s.get(k)), set: (k, v) => run('readwrite', s => s.put(v, k)), del: k => run('readwrite', s => s.delete(k)) };
}
