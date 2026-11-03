/*
 * The "Host" dialog. Only VmThings can use it: hosting needs the private host key,
 * which exists only on VmThings' device and is stored encrypted with the host password.
 */
import * as H from './host.js';
import { HOST_PUBLIC_KEY, PEER_OPTIONS } from './config.js';

const $ = s => document.querySelector(s);
const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const store = globalThis.__cyclicTestStore || H.idbStorage();
const SESSION_KEY = 'cyclic-host-session';     // sessionStorage: this tab only, gone when the tab closes, never sent over the network
const sleep = ms => new Promise(r => setTimeout(r, ms));
let running = null, sqlPromise = null;

const loadSql = () => globalThis.__cyclicTestSQL ? Promise.resolve(globalThis.__cyclicTestSQL) : sqlPromise ||= new Promise((res, rej) => {
  const s = document.createElement('script'); s.src = 'host/vendor/sql-wasm.js';
  s.onload = () => initSqlJs({ locateFile: f => 'host/vendor/' + f }).then(res, rej);
  s.onerror = () => rej(new Error('Couldn’t load the database engine.'));
  document.head.appendChild(s);
});
function download(name, data, type) {
  const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([data], { type })); a.download = name; a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 5000);
}
const readFile = f => new Promise((res, rej) => { const r = new FileReader(); r.onload = () => res(r.result); r.onerror = rej; r.readAsArrayBuffer(f); });
const keyLine = pub => `export const HOST_PUBLIC_KEY = ${JSON.stringify(H.publicOf(pub))};`;

// Starts hosting from an already-unlocked key. After a page refresh the broker may still hold the old
// connection ID for a few seconds, so a resume retries instead of failing.
async function startWith({ privateJwk, publicJwk, stripeKey }, { retry = 0 } = {}) {
  if (HOST_PUBLIC_KEY && !H.sameKey(publicJwk, HOST_PUBLIC_KEY)) throw new Error('This device’s key doesn’t match the host key published on the site.');
  const SQL = await loadSql();
  for (let attempt = 0; ; attempt++) {
    running = await H.startHost({
      SQL, storage: store, Peer: window.Peer, privateJwk, publicJwk, stripeKey,
      siteUrl: new URL('.', location.href).href, peerOptions: PEER_OPTIONS, onStatus: paint
    });
    if (retry) for (let i = 0; i < 40 && running.status.state === 'starting'; i++) await sleep(100);
    if (retry && attempt < retry && running.status.state === 'error' && /already hosting/.test(running.status.lastError || '')) {
      running.stop(); running = null; await sleep(3000); continue;
    }
    break;
  }
  window.CyclicHostLocal = (m, p, b, t) => running.call(m, p, b, t);
  window.dispatchEvent(new Event('cyclic-host-local'));
}
async function begin(password, stripeInput) {
  const rec = await store.get('hostkey');
  const privateJwk = await H.unlock(rec.blob, password);                 // throws "Wrong password."
  let stripeKey = '';
  if (stripeInput) { await store.set('stripe', await H.lock({ key: stripeInput }, password)); stripeKey = stripeInput; }
  else { const sb = await store.get('stripe'); if (sb) stripeKey = (await H.unlock(sb, password)).key; }
  const data = { privateJwk, publicJwk: rec.publicJwk, stripeKey };
  await startWith(data);
  try { sessionStorage.setItem(SESSION_KEY, JSON.stringify(data)); } catch { /* private mode: you'll just retype the password after a refresh */ }
}
function stop() {
  try { sessionStorage.removeItem(SESSION_KEY); } catch { /* nothing saved */ }
  if (running) running.stop();
  running = null; window.CyclicHostLocal = null; window.dispatchEvent(new Event('cyclic-host-local'));
}

const STATE = { starting: 'Starting…', online: 'Online. Visitors can connect.', reconnecting: 'Reconnecting…', error: 'Problem', stopped: 'Stopped' };
function paint(st) {
  const el = $('#hStatus'); if (!el) return;
  el.innerHTML = `<b>${esc(STATE[st.state] || st.state)}</b><br>
    <span class="hint">Visitors connected: ${st.clients} · Stripe checked: ${st.lastPoll ? new Date(st.lastPoll).toLocaleTimeString() : 'not yet'} · Events applied: ${st.processed}</span>
    ${st.lastError ? `<p class="err">${esc(st.lastError)}</p>` : ''}`;
}

async function render() {
  const body = $('#hostBody'), rec = await store.get('hostkey'), hasStripe = !!(await store.get('stripe'));
  if (running) {
    body.innerHTML = `<div id="hStatus"></div>
      <div class="note">Keep this tab open. When it closes, the Cyclic host goes offline: nobody can sign in, buy credits or start a session until you host again.</div>
      <div style="display:flex;gap:8px;flex-wrap:wrap;margin:10px 0">
        <button class="btn" id="hPoll">Check Stripe now</button>
        <button class="btn ghost" id="hDb">Download database backup</button>
        <button class="btn ghost" id="hKey">Download key backup</button>
        <button class="btn ghost" id="hStop">Stop hosting</button>
      </div>
      ${HOST_PUBLIC_KEY ? '' : `<h3 style="margin:14px 0 6px">Publish your host key</h3><p class="hint">Visitors can’t verify you until the site knows your public key. Replace the <code>HOST_PUBLIC_KEY</code> line in <code>host/config.js</code> with this and upload the file:</p><pre id="hPub">${esc(keyLine(rec.publicJwk))}</pre><button class="btn ghost sm" id="hCopy">Copy</button>`}
      <p class="err" id="hErr" role="alert"></p>`;
    paint(running.status);
    $('#hPoll').onclick = async () => { $('#hPoll').disabled = true; const r = await running.stripePoll(); $('#hErr').textContent = ''; $('#hPoll').disabled = false; toast(`Checked Stripe: ${r.processed} new events`); };
    $('#hDb').onclick = () => download('cyclic-database-' + new Date().toISOString().slice(0, 10) + '.sqlite', running.exportDb(), 'application/x-sqlite3');
    $('#hKey').onclick = async () => download('cyclic-host-key.json', JSON.stringify({ hostkey: rec, stripe: await store.get('stripe') || null }), 'application/json');
    $('#hStop').onclick = () => { stop(); render(); };
    if ($('#hCopy')) $('#hCopy').onclick = () => navigator.clipboard.writeText($('#hPub').textContent).then(() => toast('Copied'));
    return;
  }
  if (rec) {
    body.innerHTML = `<p>Enter your host password to start hosting on this device.</p>
      <form id="hForm"><div class="f"><label for="hPw">Host password</label><input type="password" id="hPw" required autocomplete="current-password"></div>
      <div class="f"><label for="hStripe">Stripe key ${hasStripe ? '(saved. Leave empty to keep it)' : '(optional now)'}</label><input type="password" id="hStripe" autocomplete="off" placeholder="rk_live_… or rk_test_…"><div class="hint">Use a restricted key. It’s stored encrypted with your host password and never leaves this device except to call Stripe.</div></div>
      <button class="btn" id="hGo">Start hosting</button> <button type="button" class="btn ghost" id="hRestore">Restore database…</button>
      <input type="file" id="hFile" hidden></form><p class="err" id="hErr" role="alert"></p>`;
    $('#hForm').onsubmit = async e => {
      e.preventDefault(); $('#hGo').disabled = true; $('#hErr').textContent = '';
      try { await begin($('#hPw').value, $('#hStripe').value.trim()); render(); } catch (err) { $('#hErr').textContent = err.message; $('#hGo').disabled = false; }
    };
    $('#hRestore').onclick = () => $('#hFile').click();
    $('#hFile').onchange = async ev => {
      const f = ev.target.files[0]; if (!f) return;
      const bytes = new Uint8Array(await readFile(f));
      if (new TextDecoder().decode(bytes.slice(0, 15)) !== 'SQLite format 3') { $('#hErr').textContent = 'That isn’t a Cyclic database backup.'; return; }
      if (!confirm('Replace the database on this device with this backup?')) return;
      await store.set('db', bytes); toast('Database restored. Start hosting to use it.');
    };
    return;
  }
  if (HOST_PUBLIC_KEY) {                          // the site already has a host; this device doesn't hold its key
    body.innerHTML = `<p><b>Hosting is only available to VmThings, on their own device.</b></p>
      <p class="hint">Visitors only trust a host that can prove it holds the site’s host key, and that key isn’t on this device. If you’re VmThings and moving to a new device, import your key backup here.</p>
      <button class="btn ghost" id="hImport">Import key backup…</button><input type="file" id="hFile" hidden accept=".json"><p class="err" id="hErr" role="alert"></p>`;
    $('#hImport').onclick = () => $('#hFile').click();
    $('#hFile').onchange = async ev => {
      try {
        const j = JSON.parse(new TextDecoder().decode(new Uint8Array(await readFile(ev.target.files[0]))));
        if (!j.hostkey || !H.sameKey(j.hostkey.publicJwk, HOST_PUBLIC_KEY)) throw new Error('That key isn’t this site’s host key.');
        await store.set('hostkey', j.hostkey); if (j.stripe) await store.set('stripe', j.stripe); render();
      } catch (err) { $('#hErr').textContent = err.message; }
    };
    return;
  }
  body.innerHTML = `<p>No one is hosting yet. Set this device up as the Cyclic host. You only do this once, and only VmThings should.</p>
    <form id="hForm">
      <div class="f"><label for="hEmail">Your email (for the VmThings account)</label><input type="email" id="hEmail" required></div>
      <div class="f"><label for="hPw">Host password</label><input type="password" id="hPw" required minlength="8" autocomplete="new-password"><div class="hint">Also your VmThings account password. It protects the host key. If you lose it, the key can’t be recovered.</div></div>
      <div class="f"><label for="hPw2">Repeat password</label><input type="password" id="hPw2" required autocomplete="new-password"></div>
      <div class="f"><label for="hStripe">Stripe key (optional now)</label><input type="password" id="hStripe" autocomplete="off" placeholder="rk_live_… or rk_test_…"><div class="hint">Add it later by hosting again. Use a restricted key.</div></div>
      <button class="btn" id="hGo">Set up and start hosting</button></form><p class="err" id="hErr" role="alert"></p>`;
  $('#hForm').onsubmit = async e => {
    e.preventDefault(); $('#hErr').textContent = '';
    const pw = $('#hPw').value;
    if (pw !== $('#hPw2').value) { $('#hErr').textContent = 'The passwords don’t match.'; return; }
    $('#hGo').disabled = true;
    try {
      const { privateJwk, publicJwk } = await H.generateHostKey();
      await store.set('hostkey', { blob: await H.lock(privateJwk, pw), publicJwk });
      await begin(pw, $('#hStripe').value.trim());
      try { await running.createOwner({ email: $('#hEmail').value, password: pw }); }
      catch (err) { stop(); await store.del('hostkey'); await store.del('stripe'); throw err; }   // nothing half-made
      render();
    } catch (err) { $('#hErr').textContent = err.message; $('#hGo').disabled = false; }
  };
}
function toast(t) { const e = document.createElement('div'); e.className = 'toast'; e.textContent = t; document.body.appendChild(e); setTimeout(() => e.remove(), 3000); }

(async () => {                                   // refresh: pick hosting back up without the password
  let raw = null; try { raw = sessionStorage.getItem(SESSION_KEY); } catch { /* unavailable */ }
  if (!raw) return;
  try { await startWith(JSON.parse(raw), { retry: 10 }); toast('Hosting resumed'); }
  catch (err) { console.error(err); try { sessionStorage.removeItem(SESSION_KEY); } catch { /* ignore */ } }
})();

window.addEventListener('beforeunload', e => { if (running) { running.flush(); e.preventDefault(); e.returnValue = ''; } });
window.CyclicHostUI = { open() { $('#hostDlg').showModal(); render(); } };
const btn = $('#hostBtn'); if (btn) btn.onclick = () => window.CyclicHostUI.open();
$('#hClose') && ($('#hClose').onclick = () => $('#hostDlg').close());
