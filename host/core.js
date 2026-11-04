/*
 * Cyclic core – the "server" logic: accounts, credit balances, Stripe payments
 * and volunteer payouts. It runs inside VmThings' browser (see host.js), with a
 * SQLite database on that device. It only needs fetch, crypto.subtle and an
 * env.DB with a D1-style interface.
 *
 * Volunteers host their own Pi. A Pi only starts a session when this core
 * (holding that device's secret) tells it to, after taking credits from the user.
 * There is no webhook: pollStripe() reads Stripe's event list instead.
 */
export const SCHEMA = `
CREATE TABLE IF NOT EXISTS users(
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  pw_hash TEXT NOT NULL,
  pw_salt TEXT NOT NULL,
  credits INTEGER NOT NULL DEFAULT 0,
  stripe_customer TEXT,
  stripe_sub TEXT,
  sub_status TEXT,
  sub_cancel INTEGER NOT NULL DEFAULT 0,
  connect_account TEXT,
  connect_ready INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS devices(
  id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL,
  api_url TEXT UNIQUE NOT NULL,
  secret TEXT NOT NULL,
  price_cents INTEGER NOT NULL DEFAULT 0,
  online INTEGER NOT NULL DEFAULT 0,
  last_seen INTEGER NOT NULL DEFAULT 0,
  checked_at INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);
-- Every credit movement. "ref" is unique so a Stripe event can never grant credits twice.
CREATE TABLE IF NOT EXISTS ledger(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL,
  delta INTEGER NOT NULL,
  reason TEXT NOT NULL,
  ref TEXT UNIQUE,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions(
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  credits INTEGER NOT NULL,
  earned_cents INTEGER NOT NULL,
  started_at INTEGER NOT NULL
);
-- Money owed to volunteers. Held for HOLD_DAYS, then paid out through Stripe Connect.
CREATE TABLE IF NOT EXISTS earnings(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL,
  cents INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  paid INTEGER NOT NULL DEFAULT 0,
  payout_ref TEXT
);
CREATE INDEX IF NOT EXISTS earnings_user ON earnings(user_id, paid);
CREATE INDEX IF NOT EXISTS devices_owner ON devices(owner_id);
CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS teams(owner_id TEXT PRIMARY KEY, seats INTEGER NOT NULL, code TEXT UNIQUE NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS team_members(user_id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, joined_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS session_log(session_id TEXT PRIMARY KEY, device_name TEXT, minutes INTEGER);
CREATE TABLE IF NOT EXISTS platform_fees(ref TEXT PRIMARY KEY, cents INTEGER NOT NULL, created_at INTEGER NOT NULL);
`;

const enc = new TextEncoder();
const DAY = 86400000;
const PACKS = [500, 1000, 2500, 5000];            // credit shop, in cents

/* ---------- helpers ---------- */
const num = (v, d) => { const n = parseInt(v, 10); return Number.isFinite(n) ? n : d; };
const conf = env => ({
  cc: Math.max(1, num(env.CREDIT_CENTS, 10)), fee: Math.min(100, Math.max(0, num(env.FEE_PERCENT, 0))),
  hold: num(env.HOLD_DAYS, 7), minPayout: num(env.MIN_PAYOUT_CENTS, 500), planMin: num(env.PLAN_MIN_CENTS, 500),
  // Perk: extra credits on every subscription payment. Paid for by the host, not by volunteers.
  bonusStd: Math.min(100, Math.max(0, num(env.BONUS_STANDARD_PERCENT, 5))), bonusEnt: Math.min(100, Math.max(0, num(env.BONUS_ENTERPRISE_PERCENT, 10))),
  entFee: Math.max(0, num(env.ENTERPRISE_FEE_CENTS, 1000))      // Enterprise: the flat $10 that goes to the host
});
const MIN_SEATS = 2, MAX_SEATS = 500;
const b64u = u8 => btoa(String.fromCharCode(...u8)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const hex = u8 => [...u8].map(b => b.toString(16).padStart(2, '0')).join('');
const fromHex = h => Uint8Array.from(h.match(/../g) || [], x => parseInt(x, 16));
const randHex = n => hex(crypto.getRandomValues(new Uint8Array(n)));
const safeEq = (a, b) => { if (a.length !== b.length) return false; let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i); return r === 0; };
async function hmac(secret, data) {
  const k = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, enc.encode(data)));
}
async function hashPw(pw, saltHex) {
  const k = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: fromHex(saltHex), iterations: 100000 }, k, 256);
  return hex(new Uint8Array(bits));
}
class HttpError extends Error { constructor(s, m) { super(m); this.status = s; } }
const fail = (s, m) => { throw new HttpError(s, m); };
const cors = env => ({
  'Access-Control-Allow-Origin': env.SITE_ORIGIN || '*', 'Vary': 'Origin',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS'
});
const json = (env, data, status = 200) => new Response(JSON.stringify(data), {
  status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...cors(env) }
});
const readJson = async req => { try { return await req.json(); } catch { return {}; } };
const siteUrl = (env, qs = '', hash = '') => env.SITE_URL.replace(/\/?$/, '/') + qs + hash;

/* ---------- Stripe (plain fetch, no SDK) ---------- */
function flat(o, prefix, out = []) {
  for (const [k, v] of Object.entries(o)) {
    if (v == null) continue;
    const key = prefix ? `${prefix}[${k}]` : k;
    if (typeof v === 'object') flat(v, key, out); else out.push([key, String(v)]);
  }
  return out;
}
async function stripe(env, method, path, params, headers = {}) {
  if (!env.STRIPE_SECRET_KEY) fail(503, 'Payments aren’t set up on the host yet.');
  const opt = { method, headers: { Authorization: `Bearer ${env.STRIPE_SECRET_KEY}`, ...headers } };
  const q = params ? new URLSearchParams(flat(params)) : null;
  let url = 'https://api.stripe.com/v1' + path;
  if (q && method === 'GET') url += '?' + q;
  else if (q) { opt.body = q; opt.headers['Content-Type'] = 'application/x-www-form-urlencoded'; }
  const r = await fetch(url, opt), j = await r.json();
  if (!r.ok) fail(502, j.error?.message || 'Stripe error');
  return j;
}
/* ---------- auth ---------- */
async function signToken(env, uid) {
  const p = `${uid}.${Date.now() + 30 * DAY}`;
  return `${p}.${b64u(await hmac(env.AUTH_SECRET, p))}`;
}
async function userFrom(req, env) {
  const h = req.headers.get('Authorization') || '';
  const [uid, exp, sig] = (h.startsWith('Bearer ') ? h.slice(7) : '').split('.');
  if (!uid || !exp || !sig) fail(401, 'Please sign in.');
  if (!safeEq(sig, b64u(await hmac(env.AUTH_SECRET, `${uid}.${exp}`))) || Date.now() > +exp) fail(401, 'Your sign-in expired. Please sign in again.');
  const u = await env.DB.prepare('SELECT * FROM users WHERE id=?').bind(uid).first();
  if (!u) fail(401, 'Please sign in.');
  return u;
}

/* ---------- small helpers ---------- */
const kvGet = async (env, k) => (await env.DB.prepare('SELECT v FROM kv WHERE k=?').bind(k).first())?.v ?? null;
const kvSet = (env, k, v) => env.DB.prepare('INSERT INTO kv(k,v) VALUES(?1,?2) ON CONFLICT(k) DO UPDATE SET v=?2').bind(k, String(v)).run();
const SUB_OK = st => ['active', 'trialing', 'past_due'].includes(st);
const teamCode = () => { const A = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'; let c = ''; for (const b of crypto.getRandomValues(new Uint8Array(10))) c += A[b % A.length]; return c; };
async function ensureTeam(env, ownerId, seats) {
  if (await env.DB.prepare('SELECT 1 x FROM teams WHERE owner_id=?').bind(ownerId).first())
    await env.DB.prepare('UPDATE teams SET seats=? WHERE owner_id=?').bind(seats, ownerId).run();
  else await env.DB.prepare('INSERT INTO teams(owner_id,seats,code,created_at) VALUES(?,?,?,?)').bind(ownerId, seats, teamCode(), Date.now()).run();
}
async function teamInfo(env, u) {
  const t = await env.DB.prepare('SELECT * FROM teams WHERE owner_id=?').bind(u.id).first();
  if (t) {
    const ms = await env.DB.prepare('SELECT u.id,u.name FROM team_members m JOIN users u ON u.id=m.user_id WHERE m.owner_id=? ORDER BY m.joined_at').bind(u.id).all();
    return { role: 'owner', seats: t.seats, code: t.code, members: ms.results };
  }
  const m = await env.DB.prepare('SELECT o.name,o.credits,o.sub_status FROM team_members tm JOIN users o ON o.id=tm.owner_id WHERE tm.user_id=?').bind(u.id).first();
  return m ? { role: 'member', ownerName: m.name, active: SUB_OK(m.sub_status), pool: SUB_OK(m.sub_status) ? m.credits : 0 } : null;
}
// Perks: any active subscription, or being on a team whose plan is active.
async function hasPerks(env, u) {
  if (SUB_OK(u.sub_status)) return true;
  const m = await env.DB.prepare('SELECT o.sub_status FROM team_members tm JOIN users o ON o.id=tm.owner_id WHERE tm.user_id=?').bind(u.id).first();
  return !!m && SUB_OK(m.sub_status);
}
const loginFails = new Map();           // email -> recent failure times (in memory)
const RESERVED_NAME = /^vm\s*things$/i;

/* ---------- credits ---------- */
// Idempotent: the same ref can never grant twice (one transaction).
async function grant(env, userId, credits, reason, ref) {
  if (credits <= 0) return;
  await env.DB.batch([
    env.DB.prepare('UPDATE users SET credits=credits+?1 WHERE id=?2 AND NOT EXISTS(SELECT 1 FROM ledger WHERE ref=?3)').bind(credits, userId, ref),
    env.DB.prepare('INSERT OR IGNORE INTO ledger(user_id,delta,reason,ref,created_at) SELECT ?1,?2,?3,?4,?5 WHERE EXISTS(SELECT 1 FROM users WHERE id=?1)').bind(userId, credits, reason, ref, Date.now())
  ]);
}
async function planCents(env) {
  const { cc, planMin } = conf(env);
  const r = await env.DB.prepare('SELECT MAX(price_cents) m FROM devices WHERE online=1 AND last_seen>?').bind(Date.now() - 3 * 3600000).first();
  return Math.ceil(Math.max(planMin, r?.m || 0) / cc) * cc;
}
async function piInfo(apiUrl) {
  try {
    const r = await fetch(apiUrl + '/api/info', { signal: AbortSignal.timeout(6000) });
    return r.ok ? await r.json() : null;
  } catch { return null; }
}
async function ensureCustomer(env, u) {
  if (u.stripe_customer) return u.stripe_customer;
  const c = await stripe(env, 'POST', '/customers', { email: u.email, name: u.name, metadata: { userId: u.id } });
  await env.DB.prepare('UPDATE users SET stripe_customer=? WHERE id=?').bind(c.id, u.id).run();
  return c.id;
}

/* ---------- payouts to volunteers ---------- */
async function payoutUser(env, u, force = false) {
  const { hold, minPayout } = conf(env);
  if (!u.connect_account || !u.connect_ready) return { paid: 0, reason: 'Payouts aren’t set up yet.' };
  const cutoff = Date.now() - hold * DAY, ref = 'po_' + randHex(8);
  // Claim the rows first so two payouts can never take the same earnings.
  await env.DB.prepare('UPDATE earnings SET paid=1,payout_ref=?1 WHERE user_id=?2 AND paid=0 AND created_at<=?3').bind(ref, u.id, cutoff).run();
  const { total } = await env.DB.prepare('SELECT COALESCE(SUM(cents),0) total FROM earnings WHERE payout_ref=?').bind(ref).first();
  const release = () => env.DB.prepare('UPDATE earnings SET paid=0,payout_ref=NULL WHERE payout_ref=?').bind(ref).run();
  if (total <= 0 || (!force && total < minPayout)) { await release(); return { paid: 0, reason: total ? `The minimum payout is $${(minPayout / 100).toFixed(2)}.` : 'Nothing has cleared the hold period yet.' }; }
  try {
    await stripe(env, 'POST', '/transfers', { amount: total, currency: 'usd', destination: u.connect_account, metadata: { userId: u.id, ref } }, { 'Idempotency-Key': ref });
    return { paid: total };
  } catch (e) { await release(); return { paid: 0, reason: e.message }; }
}

/* ---------- handlers ---------- */
async function me(env, u) {
  const { hold } = conf(env), cutoff = Date.now() - hold * DAY;
  if (u.connect_account && !u.connect_ready) {
    try {
      const a = await stripe(env, 'GET', '/accounts/' + u.connect_account);
      if (a.payouts_enabled && a.details_submitted) { u.connect_ready = 1; await env.DB.prepare('UPDATE users SET connect_ready=1 WHERE id=?').bind(u.id).run(); }
    } catch { /* leave as not ready */ }
  }
  const e = await env.DB.prepare(`SELECT
      COALESCE(SUM(CASE WHEN paid=0 AND created_at>?1 THEN cents END),0) pending,
      COALESCE(SUM(CASE WHEN paid=0 AND created_at<=?1 THEN cents END),0) available,
      COALESCE(SUM(CASE WHEN paid=1 THEN cents END),0) paid FROM earnings WHERE user_id=?2`).bind(cutoff, u.id).first();
  const devs = await env.DB.prepare('SELECT id,api_url,online,price_cents FROM devices WHERE owner_id=?').bind(u.id).all();
  const team = await teamInfo(env, u), isOwner = (await kvGet(env, 'owner_id')) === u.id;
  const fees = isOwner ? (await env.DB.prepare('SELECT COALESCE(SUM(cents),0) c FROM platform_fees').first()).c : null;
  return {
    id: u.id, email: u.email, name: u.name, credits: u.credits, isOwner, feesCents: fees, team, perks: await hasPerks(env, u),
    sub: u.stripe_sub ? { status: u.sub_status, cancelAtPeriodEnd: !!u.sub_cancel, kind: team?.role === 'owner' ? 'enterprise' : 'standard' } : null,
    connect: { hasAccount: !!u.connect_account, ready: !!u.connect_ready },
    earnings: { pendingCents: e.pending, availableCents: e.available, paidCents: e.paid },
    devices: devs.results.map(d => ({ id: d.id, apiUrl: d.api_url, online: !!d.online, priceCents: d.price_cents }))
  };
}

async function startSession(req, env, u) {
  const { cc, fee } = conf(env);
  const { deviceId } = await readJson(req);
  const dev = await env.DB.prepare('SELECT * FROM devices WHERE id=?').bind(String(deviceId || '')).first();
  if (!dev) fail(404, 'That device isn’t listed any more.');
  if (dev.owner_id === u.id) fail(400, 'You can’t rent your own device.');
  const info = await piInfo(dev.api_url);
  if (!info || !info.online) fail(503, 'This device is offline.');
  if (info.status !== 'available') fail(409, 'This device is in use. Try again in a few minutes.');
  const cents = Math.round((+info.price || 0) * 100), credits = Math.ceil(cents / cc);
  const earned = Math.floor(credits * cc * (100 - fee) / 100), sid = crypto.randomUUID();

  // Team members draw on the team's shared credits first (while the plan is active), then their own.
  let payer = u.id;
  const tm = await env.DB.prepare('SELECT o.id,o.credits,o.sub_status FROM team_members m JOIN users o ON o.id=m.owner_id WHERE m.user_id=?').bind(u.id).first();
  if (tm && SUB_OK(tm.sub_status) && tm.credits >= credits) payer = tm.id;
  if (credits > 0) {
    const r = await env.DB.batch([
      env.DB.prepare('UPDATE users SET credits=credits-?1 WHERE id=?2 AND credits>=?1').bind(credits, payer),
      env.DB.prepare('INSERT INTO ledger(user_id,delta,reason,ref,created_at) SELECT ?1,?2,?3,?4,?5 WHERE changes()>0').bind(payer, -credits, 'session', 's:' + sid, Date.now())
    ]);
    if (!r[0].meta.changes) fail(402, tm ? `Your team’s credits and yours aren’t enough. This session needs ${credits}.` : `You need ${credits} credits for this session.`);
  }
  let out;
  try {
    const r = await fetch(dev.api_url + '/api/session/start', {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + dev.secret },
      body: '{}', signal: AbortSignal.timeout(8000)
    });
    out = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(out.error || 'The device refused the session.');
  } catch (e) {
    await grant(env, payer, credits, 'refund', 'r:' + sid);       // give the credits back
    fail(502, e.name === 'TimeoutError' ? 'The device didn’t respond. You weren’t charged.' : e.message + ' You weren’t charged.');
  }
  const stmts = [env.DB.prepare('INSERT INTO sessions(id,user_id,device_id,credits,earned_cents,started_at) VALUES(?,?,?,?,?,?)').bind(sid, u.id, dev.id, credits, earned, Date.now()),
    env.DB.prepare('INSERT INTO session_log(session_id,device_name,minutes) VALUES(?,?,?)').bind(sid, String(info.name || 'Android device').slice(0, 60), +info.timeLimit || 0)];
  if (earned > 0) stmts.push(env.DB.prepare('INSERT INTO earnings(user_id,cents,created_at) VALUES(?,?,?)').bind(dev.owner_id, earned, Date.now()));
  await env.DB.batch(stmts);
  const bal = await env.DB.prepare('SELECT credits FROM users WHERE id=?').bind(u.id).first();
  const pool = payer !== u.id ? (await env.DB.prepare('SELECT credits FROM users WHERE id=?').bind(payer).first()).credits : null;
  return { token: out.token, secondsLeft: out.secondsLeft, credits: bal.credits, spent: credits, paidByTeam: payer !== u.id, pool };
}

async function processEvent(env, ev) {
  const o = ev.data.object, { cc } = conf(env);
  const byCustomer = id => env.DB.prepare('SELECT * FROM users WHERE stripe_customer=?').bind(id).first();
  const subOf = i => i.subscription || i.parent?.subscription_details?.subscription || null;

  switch (ev.type) {
    case 'checkout.session.completed':
      if (o.mode === 'payment' && o.metadata?.kind === 'credits' && o.payment_status === 'paid')
        await grant(env, o.metadata.userId, num(o.metadata.credits, 0), 'purchase', 'cs:' + o.id);
      break;
    case 'invoice.paid': {            // every monthly payment becomes credits (Enterprise: minus the flat fee that goes to the host)
      const sid = subOf(o); if (!sid || !o.amount_paid) break;
      const u = await byCustomer(o.customer); if (!u) break;
      const sub = await stripe(env, 'GET', '/subscriptions/' + sid), ent = sub.metadata?.kind === 'enterprise';
      const { bonusStd, bonusEnt, entFee } = conf(env);
      const fee = ent ? Math.min(entFee, o.amount_paid) : 0;
      const base = Math.floor((o.amount_paid - fee) / cc), bonus = Math.floor(base * (ent ? bonusEnt : bonusStd) / 100);
      if (ent) await ensureTeam(env, u.id, num(sub.metadata.seats, MIN_SEATS));
      await grant(env, u.id, base, 'subscription', 'inv:' + o.id);
      await grant(env, u.id, bonus, 'subscription bonus', 'inv:' + o.id + ':bonus');
      if (fee) await env.DB.prepare('INSERT OR IGNORE INTO platform_fees(ref,cents,created_at) VALUES(?,?,?)').bind('inv:' + o.id, fee, Date.now()).run();
      break;
    }
    case 'invoice.upcoming': {        // keep the plan priced at the highest device price
      const sid = subOf(o); if (!sid) break;
      if (Date.now() / 1000 - ev.created > 5 * 86400) break;   // too old to matter
      const per = await planCents(env), sub = await stripe(env, 'GET', '/subscriptions/' + sid), item = sub.items.data[0];
      const cents = sub.metadata?.kind === 'enterprise' ? per * num(sub.metadata.seats, MIN_SEATS) + conf(env).entFee : per;
      if (item.price.unit_amount !== cents)
        await stripe(env, 'POST', '/subscriptions/' + sid, {
          proration_behavior: 'none',
          items: [{ id: item.id, price_data: { currency: 'usd', unit_amount: cents, product: await ensureProduct(env), recurring: { interval: 'month' } } }]
        });
      break;
    }
    case 'customer.subscription.created':
    case 'customer.subscription.updated':
      await env.DB.prepare('UPDATE users SET stripe_sub=?,sub_status=?,sub_cancel=? WHERE stripe_customer=?').bind(o.id, o.status, o.cancel_at_period_end ? 1 : 0, o.customer).run();
      if (o.metadata?.kind === 'enterprise' && o.metadata.userId) await ensureTeam(env, o.metadata.userId, num(o.metadata.seats, MIN_SEATS));
      break;
    case 'customer.subscription.deleted': {
      const owner = await byCustomer(o.customer);
      await env.DB.prepare('UPDATE users SET stripe_sub=NULL,sub_status=NULL,sub_cancel=0 WHERE stripe_customer=?').bind(o.customer).run();
      if (owner) await env.DB.batch([     // a cancelled Enterprise plan ends the team (the owner keeps their own credits)
        env.DB.prepare('DELETE FROM team_members WHERE owner_id=?').bind(owner.id),
        env.DB.prepare('DELETE FROM teams WHERE owner_id=?').bind(owner.id)]);
      break;
    }
  }
}

const EVENT_TYPES = ['checkout.session.completed', 'invoice.paid', 'invoice.upcoming',
  'customer.subscription.created', 'customer.subscription.updated', 'customer.subscription.deleted'];

// Reads Stripe's recent events (kept for 30 days) and applies the ones not seen yet.
// Safe to run as often as you like: every grant is idempotent.
export async function pollStripe(env) {
  if (!env.STRIPE_SECRET_KEY) return { processed: 0 };
  const fresh = []; let after = null;
  scan: for (let page = 0; page < 5; page++) {
    const r = await stripe(env, 'GET', '/events', { limit: 100, types: EVENT_TYPES, ...(after ? { starting_after: after } : {}) });
    for (const ev of r.data) {
      if (await env.DB.prepare('SELECT 1 x FROM events WHERE id=?').bind(ev.id).first()) break scan;
      fresh.push(ev);
    }
    if (!r.has_more || !r.data.length) break;
    after = r.data[r.data.length - 1].id;
  }
  let processed = 0;
  for (const ev of fresh.reverse()) {              // oldest first
    try {
      await processEvent(env, ev);
      await env.DB.prepare('INSERT OR IGNORE INTO events(id,created_at) VALUES(?,?)').bind(ev.id, Date.now()).run();
      processed++;
    } catch (e) { console.error('Stripe event', ev.id, ev.type, 'failed:', e.message); }
  }
  return { processed };
}

export async function ensureProduct(env) {
  if (env.STRIPE_PRODUCT_ID) return env.STRIPE_PRODUCT_ID;
  let id = await kvGet(env, 'product_id');
  if (!id) { id = (await stripe(env, 'POST', '/products', { name: 'Cyclic subscription' })).id; await kvSet(env, 'product_id', id); }
  return id;
}

// Creates the owner account (VmThings). Only the host runtime can call this.
export async function createOwner(env, { email, password }) {
  if (await kvGet(env, 'owner_id')) fail(409, 'The owner account already exists.');
  email = String(email || '').trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) fail(400, 'Enter a valid email address.');
  if (String(password || '').length < 8) fail(400, 'Use a password of at least 8 characters.');
  const id = crypto.randomUUID(), salt = randHex(16);
  await env.DB.prepare('INSERT INTO users(id,email,name,pw_hash,pw_salt,created_at) VALUES(?,?,?,?,?,?)').bind(id, email, 'VmThings', await hashPw(password, salt), salt, Date.now()).run();
  await kvSet(env, 'owner_id', id);
  return id;
}

async function route(req, env, url) {
  const p = url.pathname, m = req.method;
  const { cc, fee, hold, minPayout } = conf(env);

  if (m === 'GET' && p === '/config') {
    const cents = await planCents(env);
    const k = conf(env);
    return {
      creditCents: cc, packs: PACKS.map(c => ({ cents: c, credits: c / cc })), plan: { cents, credits: cents / cc }, holdDays: hold, minPayoutCents: minPayout, feePercent: fee,
      enterprise: { perPersonCents: cents, feeCents: k.entFee, minSeats: MIN_SEATS, maxSeats: MAX_SEATS },
      perks: { standardBonusPercent: k.bonusStd, enterpriseBonusPercent: k.bonusEnt }
    };
  }
  if (m === 'POST' && p === '/auth/signup') {
    const b = await readJson(req), email = String(b.email || '').trim().toLowerCase(), name = String(b.name || '').trim().slice(0, 30), pw = String(b.password || '');
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) fail(400, 'Enter a valid email address.');
    if (!name) fail(400, 'Enter a display name.');
    if (RESERVED_NAME.test(name)) fail(400, 'That name is reserved.');
    if (pw.length < 8 || pw.length > 200) fail(400, 'Use a password of at least 8 characters.');
    if (await env.DB.prepare('SELECT 1 x FROM users WHERE email=?').bind(email).first()) fail(409, 'That email already has an account. Sign in instead.');
    const id = crypto.randomUUID(), salt = randHex(16);
    await env.DB.prepare('INSERT INTO users(id,email,name,pw_hash,pw_salt,created_at) VALUES(?,?,?,?,?,?)').bind(id, email, name, await hashPw(pw, salt), salt, Date.now()).run();
    return { token: await signToken(env, id) };
  }
  if (m === 'POST' && p === '/auth/login') {
    const b = await readJson(req), em = String(b.email || '').trim().toLowerCase();
    const recent = (loginFails.get(em) || []).filter(t => Date.now() - t < 600000);
    if (recent.length >= 8) fail(429, 'Too many wrong passwords. Wait 10 minutes and try again.');
    const u = await env.DB.prepare('SELECT * FROM users WHERE email=?').bind(em).first();
    const h = await hashPw(String(b.password || ''), u ? u.pw_salt : '00'.repeat(16));
    if (!u || !safeEq(h, u.pw_hash)) { recent.push(Date.now()); loginFails.set(em, recent); fail(401, 'Wrong email or password.'); }
    loginFails.delete(em);
    return { token: await signToken(env, u.id) };
  }
  if (m === 'GET' && p === '/devices') {
    const r = await env.DB.prepare('SELECT d.id,d.api_url,u.name volunteer FROM devices d JOIN users u ON u.id=d.owner_id ORDER BY d.created_at').all();
    return { devices: r.results.map(d => ({ id: d.id, apiUrl: d.api_url, volunteer: d.volunteer })) };
  }

  const u = await userFrom(req, env);                      // everything below needs sign-in

  if (m === 'GET' && p === '/me') return me(env, u);

  if (m === 'POST' && p === '/devices') {
    const b = await readJson(req); let apiUrl = String(b.apiUrl || '').trim().replace(/\/+$/, '');
    if (!/^https:\/\/[^\s/]+(\/[^\s]*)?$/i.test(apiUrl)) fail(400, 'Enter your tunnel link starting with https://');
    const n = await env.DB.prepare('SELECT COUNT(*) c FROM devices WHERE owner_id=?').bind(u.id).first();
    if (n.c >= 5) fail(400, 'You can list up to 5 devices.');
    if (await env.DB.prepare('SELECT 1 x FROM devices WHERE api_url=?').bind(apiUrl).first()) fail(409, 'That link is already listed.');
    const info = await piInfo(apiUrl);
    if (!info || !info.online) fail(400, 'Couldn’t read a phone from that link. Check the agent is running, the tunnel points at port 8080, and adb shows the phone as “device”.');
    if ((info.currency || 'USD') !== 'USD') fail(400, 'Set "currency": "USD" in your Pi’s config.json. Credits are priced in US dollars.');
    const id = randHex(4), secret = randHex(24), now = Date.now();
    await env.DB.prepare('INSERT INTO devices(id,owner_id,api_url,secret,price_cents,online,last_seen,checked_at,created_at) VALUES(?,?,?,?,?,1,?,?,?)')
      .bind(id, u.id, apiUrl, secret, Math.round((+info.price || 0) * 100), now, now, now).run();
    return { id, apiUrl, secret };
  }
  let mm;
  if ((mm = p.match(/^\/devices\/([a-f0-9]+)$/)) && m === 'DELETE') {
    await env.DB.prepare('DELETE FROM devices WHERE id=? AND owner_id=?').bind(mm[1], u.id).run();
    return { ok: true };
  }
  if ((mm = p.match(/^\/devices\/([a-f0-9]+)\/rotate$/)) && m === 'POST') {
    const secret = randHex(24);
    const r = await env.DB.prepare('UPDATE devices SET secret=? WHERE id=? AND owner_id=?').bind(secret, mm[1], u.id).run();
    if (!r.meta.changes) fail(404, 'Device not found.');
    return { secret };
  }

  if (m === 'POST' && p === '/sessions/start') return startSession(req, env, u);

  if (m === 'POST' && p === '/shop/checkout') {
    const b = await readJson(req), cents = +b.cents;
    if (!PACKS.includes(cents)) fail(400, 'Pick one of the credit packs.');
    const credits = cents / cc, customer = await ensureCustomer(env, u);
    const s = await stripe(env, 'POST', '/checkout/sessions', {
      mode: 'payment', customer, success_url: siteUrl(env, '?checkout=success', '#shop'), cancel_url: siteUrl(env, '', '#shop'),
      line_items: [{ quantity: 1, price_data: { currency: 'usd', unit_amount: cents, product_data: { name: `${credits} Cyclic credits` } } }],
      metadata: { kind: 'credits', userId: u.id, credits }
    });
    return { url: s.url };
  }
  if (m === 'POST' && p === '/shop/subscribe') {
    if (['active', 'trialing', 'past_due'].includes(u.sub_status)) fail(409, 'You’re already subscribed. Use Manage subscription.');
    const cents = await planCents(env), customer = await ensureCustomer(env, u);
    const s = await stripe(env, 'POST', '/checkout/sessions', {
      mode: 'subscription', customer, success_url: siteUrl(env, '?checkout=success', '#shop'), cancel_url: siteUrl(env, '', '#shop'),
      line_items: [{ quantity: 1, price_data: { currency: 'usd', unit_amount: cents, product: await ensureProduct(env), recurring: { interval: 'month' } } }],
      subscription_data: { metadata: { userId: u.id } }, metadata: { kind: 'subscription', userId: u.id }
    });
    return { url: s.url };
  }
  if (m === 'POST' && p === '/shop/enterprise') {
    const b = await readJson(req), seats = Math.floor(+b.seats);
    if (!(seats >= MIN_SEATS && seats <= MAX_SEATS)) fail(400, `Enter a number of people from ${MIN_SEATS} to ${MAX_SEATS}.`);
    if (SUB_OK(u.sub_status)) fail(409, 'You’re already subscribed. Use Manage subscription.');
    if (await env.DB.prepare('SELECT 1 x FROM team_members WHERE user_id=?').bind(u.id).first()) fail(409, 'You’re on someone else’s team. Leave it first.');
    const per = await planCents(env), cents = per * seats + conf(env).entFee, customer = await ensureCustomer(env, u);
    const s = await stripe(env, 'POST', '/checkout/sessions', {
      mode: 'subscription', customer, success_url: siteUrl(env, '?checkout=success', '#shop'), cancel_url: siteUrl(env, '', '#shop'),
      line_items: [{ quantity: 1, price_data: { currency: 'usd', unit_amount: cents, product: await ensureProduct(env), recurring: { interval: 'month' } } }],
      subscription_data: { metadata: { userId: u.id, kind: 'enterprise', seats } }, metadata: { kind: 'enterprise', userId: u.id, seats }
    });
    return { url: s.url, cents };
  }
  if (m === 'POST' && p === '/team/join') {
    const b = await readJson(req), t = await env.DB.prepare('SELECT * FROM teams WHERE code=?').bind(String(b.code || '').trim().toUpperCase()).first();
    if (!t) fail(404, 'That invite code isn’t valid.');
    if (t.owner_id === u.id) fail(400, 'That’s your own team.');
    if (await env.DB.prepare('SELECT 1 x FROM teams WHERE owner_id=?').bind(u.id).first()) fail(400, 'You run a team of your own.');
    if (await env.DB.prepare('SELECT 1 x FROM team_members WHERE user_id=?').bind(u.id).first()) fail(409, 'You’re already on a team. Leave it first.');
    const owner = await env.DB.prepare('SELECT sub_status FROM users WHERE id=?').bind(t.owner_id).first();
    if (!owner || !SUB_OK(owner.sub_status)) fail(400, 'That team’s plan isn’t active.');
    const r = await env.DB.prepare('INSERT INTO team_members(user_id,owner_id,joined_at) SELECT ?1,?2,?3 WHERE (SELECT COUNT(*) FROM team_members WHERE owner_id=?2)+1 < ?4')
      .bind(u.id, t.owner_id, Date.now(), t.seats).run();
    if (!r.meta.changes) fail(409, 'That team is full.');
    return { ok: true };
  }
  if (m === 'POST' && p === '/team/leave') { await env.DB.prepare('DELETE FROM team_members WHERE user_id=?').bind(u.id).run(); return { ok: true }; }
  if (m === 'POST' && p === '/team/remove') {
    const b = await readJson(req);
    await env.DB.prepare('DELETE FROM team_members WHERE user_id=? AND owner_id=?').bind(String(b.userId || ''), u.id).run();
    return { ok: true };
  }
  if (m === 'POST' && p === '/team/code') {
    const code = teamCode(), r = await env.DB.prepare('UPDATE teams SET code=? WHERE owner_id=?').bind(code, u.id).run();
    if (!r.meta.changes) fail(404, 'You don’t have a team.');
    return { code };
  }
  if (m === 'GET' && p === '/team/usage') {
    if (!(await env.DB.prepare('SELECT 1 x FROM teams WHERE owner_id=?').bind(u.id).first())) fail(404, 'You don’t have a team.');
    const r = await env.DB.prepare(`SELECT u.name name, COUNT(*) sessions, COALESCE(SUM(s.credits),0) credits FROM sessions s JOIN users u ON u.id=s.user_id
      WHERE s.started_at>?2 AND s.user_id IN (SELECT user_id FROM team_members WHERE owner_id=?1 UNION SELECT ?1) GROUP BY s.user_id ORDER BY credits DESC`).bind(u.id, Date.now() - 30 * DAY).all();
    return { days: 30, members: r.results };
  }
  if (m === 'GET' && p === '/sessions/history') {
    const perks = await hasPerks(env, u);          // perk: full history; everyone else sees the latest 3
    const r = await env.DB.prepare(`SELECT s.id,s.started_at,s.credits,l.device_name name,l.minutes FROM sessions s LEFT JOIN session_log l ON l.session_id=s.id
      WHERE s.user_id=? ORDER BY s.started_at DESC LIMIT ?`).bind(u.id, perks ? 200 : 3).all();
    return { sessions: r.results, limited: !perks };
  }
  if (m === 'POST' && p === '/billing/portal') {
    if (!u.stripe_customer) fail(400, 'You don’t have a subscription yet.');
    const s = await stripe(env, 'POST', '/billing_portal/sessions', { customer: u.stripe_customer, return_url: siteUrl(env, '', '#shop') });
    return { url: s.url };
  }

  if (m === 'POST' && p === '/volunteer/connect') {
    let acct = u.connect_account;
    if (!acct) {
      acct = (await stripe(env, 'POST', '/accounts', { type: 'express', email: u.email, capabilities: { transfers: { requested: true } }, metadata: { userId: u.id } })).id;
      await env.DB.prepare('UPDATE users SET connect_account=? WHERE id=?').bind(acct, u.id).run();
    }
    const l = await stripe(env, 'POST', '/account_links', { account: acct, type: 'account_onboarding', refresh_url: siteUrl(env, '', '#volunteer'), return_url: siteUrl(env, '?connect=done', '#volunteer') });
    return { url: l.url };
  }
  if (m === 'POST' && p === '/volunteer/payout') {
    const r = await payoutUser(env, u);
    if (!r.paid) fail(400, r.reason);
    return r;
  }
  fail(404, 'Not found');
}

// Hourly: refresh device prices (for the subscription price); once a day: pay volunteers.
export async function cron(env) {
  const { results } = await env.DB.prepare('SELECT id,api_url FROM devices ORDER BY checked_at LIMIT 40').all();
  await Promise.all(results.map(async d => {
    const i = await piInfo(d.api_url), now = Date.now();
    if (i && i.online) await env.DB.prepare('UPDATE devices SET online=1,price_cents=?,last_seen=?,checked_at=? WHERE id=?').bind(Math.round((+i.price || 0) * 100), now, now, d.id).run();
    else await env.DB.prepare('UPDATE devices SET online=0,checked_at=? WHERE id=?').bind(now, d.id).run();
  }));
  if (Date.now() - num(await kvGet(env, 'last_payout'), 0) >= DAY) {
    await kvSet(env, 'last_payout', Date.now());
    const us = await env.DB.prepare('SELECT * FROM users WHERE connect_ready=1').all();
    for (const u of us.results) await payoutUser(env, u);
  }
}

export default {
  async fetch(req, env) {
    try { return json(env, await route(req, env, new URL(req.url))); }
    catch (e) {
      if (e instanceof HttpError) return json(env, { error: e.message }, e.status);
      console.error(e); return json(env, { error: 'Something went wrong on our side.' }, 500);
    }
  }
};
