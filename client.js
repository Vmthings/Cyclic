/*
 * Cyclic visitor side: connects to VmThings' host over WebRTC (PeerJS),
 * checks the host's signature, and sends it requests.
 * Sets window.CyclicNet = { request, onState, state } for the page to use.
 */
import { verifyHello, hostPeerId, b64 } from './host.js';

export function createClient({ Peer, publicJwk, peerOptions = {}, timeoutMs = 15000, retryMs = 10000, local = () => null }) {
  let peer = null, conn = null, state = publicJwk ? 'connecting' : 'unconfigured', timer = null, seq = 0;
  const pending = new Map(), listeners = new Set();
  const set = s => { if (s !== state) { state = s; listeners.forEach(f => f(s)); } };

  async function connect() {
    if (!publicJwk) return;
    teardown(); set('connecting');
    const hostId = await hostPeerId(publicJwk);
    peer = new Peer(undefined, peerOptions);
    peer.on('error', e => { if (e.type === 'peer-unavailable') set('offline'); else if (state !== 'online') set('offline'); });
    peer.on('open', () => {
      conn = peer.connect(hostId, { reliable: true, serialization: 'json' });
      conn.on('open', async () => {
        const nonce = b64(crypto.getRandomValues(new Uint8Array(16)));
        conn._nonce = nonce; conn.send({ t: 'hello', nonce });
      });
      conn.on('data', async msg => {
        if (msg?.t === 'hello') {
          if (await verifyHello(publicJwk, conn._nonce, msg.sig)) set('online');
          else { set('impostor'); conn.close(); }
        } else if (msg?.t === 'res' && pending.has(msg.id)) {
          const p = pending.get(msg.id); pending.delete(msg.id); clearTimeout(p.t); p.res({ status: msg.status, data: msg.data });
        }
      });
      conn.on('close', () => { if (state === 'online' || state === 'connecting') set('offline'); failAll('The connection to the host closed.'); });
      conn.on('error', () => set('offline'));
    });
  }
  function failAll(msg) { pending.forEach(p => { clearTimeout(p.t); p.rej(new Error(msg)); }); pending.clear(); }
  function teardown() { failAll('Reconnecting…'); try { conn && conn.close(); } catch { /* closed */ } try { peer && peer.destroy(); } catch { /* destroyed */ } conn = peer = null; }

  function start() {
    connect();
    timer = setInterval(() => { if (state === 'offline' || state === 'connecting') connect(); }, retryMs);
  }
  async function request(method, path, body, token) {
    const l = local();
    if (l) return l(method, path, body, token);                 // VmThings' own tab
    if (state !== 'online') throw new Error(state === 'impostor' ? 'Warning: something is pretending to be the Cyclic host. Nothing was sent.'
      : state === 'unconfigured' ? 'The Cyclic host hasn’t been set up yet.' : 'The Cyclic host (VmThings) is offline right now. Try again later.');
    const id = ++seq;
    return new Promise((res, rej) => {
      const t = setTimeout(() => { pending.delete(id); rej(new Error('The host took too long to answer.')); }, timeoutMs);
      pending.set(id, { res, rej, t });
      conn.send({ t: 'req', id, method, path, body, auth: token || undefined });
    });
  }
  return { start, request, stop() { clearInterval(timer); teardown(); }, onState(f) { listeners.add(f); f(state); }, get state() { return state; } };
}

// Browser bootstrap (skipped in tests)
if (typeof window !== 'undefined' && window.Peer && !window.__cyclicNoBoot) {
  const { HOST_PUBLIC_KEY, PEER_OPTIONS } = await import('./config.js');
  const client = createClient({ Peer: window.Peer, publicJwk: HOST_PUBLIC_KEY, peerOptions: PEER_OPTIONS, local: () => window.CyclicHostLocal || null });
  window.CyclicNet = client; client.start();
  window.dispatchEvent(new Event('cyclic-net-ready'));
}
