#!/usr/bin/env node
/*
 * Cyclic – Pi agent
 * Runs on the volunteer's Raspberry Pi. It:
 *   1. Reads the connected Android device's specs over adb.
 *   2. Hosts the API the website talks to (/api/...).
 *   3. Hosts the session: puts a session token in front of ws-scrcpy
 *      and cuts the user off when the time limit ends.
 * A session only starts when the Cyclic server asks for it (it holds your
 * device's secret, "cyclicSecret") after taking the user's credits.
 * No npm packages needed. Requires Node 18+.
 */
'use strict';
const http = require('http'), net = require('net'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const { exec } = require('child_process');

const DIR = __dirname;
const CFG_FILE = path.join(DIR, 'config.json');
const DEFAULTS = {
  host: '127.0.0.1',           // keep 127.0.0.1 when using a Cloudflare Tunnel
  port: 8080,                  // the tunnel should point here
  wsScrcpyPort: 8000,          // where ws-scrcpy is listening
  name: '',                    // leave empty to use the phone's model name
  volunteer: 'Anonymous',
  price: 0,                    // USD per session, 0 = free (rounded up to 10 cent steps)
  currency: 'USD',             // keep USD: Cyclic credits are priced in US dollars
  cyclicSecret: '',            // the device secret from your Cyclic dashboard
  timeLimitMinutes: 30,
  allowedOrigin: '*',          // set to your site, e.g. https://you.github.io
  adbSerial: '',               // only needed if more than one device is plugged in
  type: '',                    // 'phone' or 'tablet' to override auto-detect
  cleanupCommands: ['input keyevent KEYCODE_HOME'] // run on the phone after each session
};

function loadCfg() {
  try { return { ...DEFAULTS, ...JSON.parse(fs.readFileSync(CFG_FILE, 'utf8')) }; }
  catch (e) {
    if (e.code === 'ENOENT') return { ...DEFAULTS };
    console.error('Could not read config.json:', e.message); process.exit(1);
  }
}
const cfg = loadCfg();

/* ---------- adb ---------- */
const adb = args => new Promise(res =>
  exec(`adb ${cfg.adbSerial ? '-s ' + JSON.stringify(cfg.adbSerial) + ' ' : ''}${args}`, { timeout: 6000 },
    (e, o) => res(e ? null : String(o).trim())));

let cache = { t: 0, v: null };
async function deviceInfo() {
  if (cache.v && Date.now() - cache.t < 20000) return cache.v;
  const v = { online: (await adb('get-state')) === 'device' };
  if (v.online) {
    const [model, ver, chars, mem] = await Promise.all([
      adb('shell getprop ro.product.model'), adb('shell getprop ro.build.version.release'),
      adb('shell getprop ro.build.characteristics'), adb('shell cat /proc/meminfo')]);
    v.model = model || 'Android device';
    v.android = parseInt(ver, 10) || 0;
    v.type = cfg.type || ((chars || '').includes('tablet') ? 'tablet' : 'phone');
    const m = /MemTotal:\s+(\d+)/.exec(mem || ''), gb = m ? m[1] / 1048576 : 0;
    v.ram = [1, 2, 3, 4, 6, 8, 12, 16, 24].reduce((a, b) => Math.abs(b - gb) < Math.abs(a - gb) ? b : a, 1);
  }
  cache = { t: Date.now(), v };
  return v;
}

/* ---------- sessions ---------- */
let session = null, cleaning = false;
const limitMs = () => Math.max(1, +cfg.timeLimitMinutes || 30) * 60000;

function startSession() {
  const s = { token: crypto.randomBytes(24).toString('hex'), expires: Date.now() + limitMs(), sockets: new Set(), timer: null };
  s.timer = setTimeout(() => endSession(s), limitMs());
  session = s; return s;
}
async function endSession(s) {
  if (!session || session !== s) return;
  session = null; clearTimeout(s.timer); cleaning = true;
  s.sockets.forEach(x => x.destroy());
  for (const c of cfg.cleanupCommands || []) await adb('shell ' + c);
  cache.t = 0; cleaning = false;
  console.log('Session ended');
}
const secondsLeft = () => session ? Math.max(0, Math.round((session.expires - Date.now()) / 1000)) : 0;

function cookieToken(req) {
  const m = /(?:^|;\s*)sp_session=([a-f0-9]+)/.exec(req.headers.cookie || '');
  return m ? m[1] : null;
}
const authed = req => session && cookieToken(req) === session.token && Date.now() < session.expires;

/* ---------- API ---------- */
const send = (res, code, obj) => {
  res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(obj));
};
const body = req => new Promise(resolve => {
  let d = ''; req.on('data', c => { d += c; if (d.length > 10000) req.destroy(); });
  req.on('end', () => { try { resolve(JSON.parse(d || '{}')); } catch { resolve({}); } });
});

async function api(req, res, u) {
  res.setHeader('Access-Control-Allow-Origin', cfg.allowedOrigin);
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }

  if (u.pathname === '/api/info' && req.method === 'GET') {
    const d = await deviceInfo();
    return send(res, 200, {
      apiVersion: 1, online: d.online,
      name: cfg.name || d.model || 'Android device', volunteer: cfg.volunteer,
      type: d.type, android: d.android, ram: d.ram,
      timeLimit: +cfg.timeLimitMinutes, price: +cfg.price, currency: cfg.currency,
      status: !d.online ? 'offline' : (session || cleaning ? 'busy' : 'available'),
      secondsLeft: secondsLeft()
    });
  }

  if (u.pathname === '/api/session/start' && req.method === 'POST') {
    if (!cfg.cyclicSecret) return send(res, 503, { error: 'This Pi isn’t linked to Cyclic yet.' });
    const given = Buffer.from((req.headers.authorization || '').replace(/^Bearer /, ''));
    const want = Buffer.from(cfg.cyclicSecret);
    if (given.length !== want.length || !crypto.timingSafeEqual(given, want)) return send(res, 401, { error: 'Sessions can only be started through Cyclic.' });
    if (session || cleaning) return send(res, 409, { error: 'This device is in use. Try again in a few minutes.' });
    const d = await deviceInfo();
    if (!d.online) return send(res, 503, { error: 'The phone isn’t connected to the Pi right now.' });
    if (session || cleaning) return send(res, 409, { error: 'This device is in use. Try again in a few minutes.' });
    const s = startSession();
    console.log('Session started, ends in', cfg.timeLimitMinutes, 'min');
    return send(res, 200, { token: s.token, secondsLeft: secondsLeft() });
  }

  if (u.pathname === '/api/session/stop' && req.method === 'POST') {
    const b = await body(req);
    if (session && b.token === session.token) await endSession(session);
    return send(res, 200, { ok: true });
  }

  send(res, 404, { error: 'Not found' });
}

/* ---------- proxy to ws-scrcpy (only with a valid session) ---------- */
function proxy(req, res) {
  session.sockets.add(req.socket);
  const up = http.request({
    host: '127.0.0.1', port: cfg.wsScrcpyPort, path: req.url, method: req.method,
    headers: { ...req.headers, host: `127.0.0.1:${cfg.wsScrcpyPort}` }
  }, r => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
  up.on('error', () => { if (!res.headersSent) res.writeHead(502); res.end('ws-scrcpy is not running'); });
  req.pipe(up);
}

const server = http.createServer(async (req, res) => {
  try {
    const u = new URL(req.url, 'http://x');
    if (u.pathname.startsWith('/api/')) return await api(req, res, u);
    if (u.pathname === '/start') {
      const t = u.searchParams.get('t');
      if (!session || t !== session.token) { res.writeHead(403); return res.end('Session not valid or ended.'); }
      res.writeHead(302, {
        'Set-Cookie': `sp_session=${t}; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=${secondsLeft()}`,
        Location: '/'
      });
      return res.end();
    }
    if (!authed(req)) { res.writeHead(401, { 'Content-Type': 'text/plain' }); return res.end('Start a session on the website to use this device.'); }
    proxy(req, res);
  } catch (e) { console.error(e); if (!res.headersSent) res.writeHead(500); res.end(); }
});

server.on('upgrade', (req, socket, head) => {
  if (!authed(req)) { socket.destroy(); return; }
  const up = net.connect(cfg.wsScrcpyPort, '127.0.0.1', () => {
    let h = `${req.method} ${req.url} HTTP/1.1\r\n`;
    for (let i = 0; i < req.rawHeaders.length; i += 2) {
      const k = req.rawHeaders[i];
      h += `${k}: ${k.toLowerCase() === 'host' ? '127.0.0.1:' + cfg.wsScrcpyPort : req.rawHeaders[i + 1]}\r\n`;
    }
    up.write(h + '\r\n'); if (head && head.length) up.write(head);
    socket.pipe(up); up.pipe(socket);
  });
  session.sockets.add(socket); session.sockets.add(up);
  const kill = () => { socket.destroy(); up.destroy(); };
  socket.on('error', kill); up.on('error', kill);
});

server.listen(cfg.port, cfg.host, () => {
  console.log(`Cyclic agent on http://${cfg.host}:${cfg.port}`);
  console.log(`Time limit ${cfg.timeLimitMinutes} min, price ${cfg.price} ${cfg.currency}${cfg.cyclicSecret ? '' : '  (no cyclicSecret set: sessions are disabled)'}`);
  deviceInfo().then(d => console.log(d.online ? `Phone found: ${d.model} (Android ${d.android})` : 'No phone found yet. Run: adb devices'));
});
