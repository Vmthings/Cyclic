/*
 * Cyclic API – Cloudflare Worker + D1 + Stripe.
 *
 * Holds the things a static site can't: accounts, credit balances, Stripe
 * payments, and volunteer payouts. Volunteers still host their own Pi, and
 * the Pi decides who may use the phone, but a Pi only starts a session when
 * this Worker (holding that device's secret) tells it to, after taking credits
 * from the user.
 */
const enc = new TextEncoder();
const DAY = 86400000;
const PACKS = [500, 1000, 2500, 5000];            // credit shop, in cents

/* ---------- helpers ---------- */
const num = (v, d) => { const n = parseInt(v, 10); return Number.isFinite(n) ? n : d; };
const conf = env => ({
  cc: Math.max(1, num(env.CREDIT_CENTS, 10)), fee: Math.min(100, Math.max(0, num(env.FEE_PERCENT, 0))),
  hold: num(env.HOLD_DAYS, 7), minPayout: num(env.MIN_PAYOUT_CENTS, 500), planMin: num(env.PLAN_MIN_CENTS, 500)
});
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
  const opt = { method, headers: { Authorization: `Bearer ${env.STRIPE_SECRET_KEY}`, ...headers } };
  const q = params ? new URLSearchParams(flat(params)) : null;
  let url = 'https://api.stripe.com/v1' + path;
  if (q && method === 'GET') url += '?' + q;
  else if (q) { opt.body = q; opt.headers['Content-Type'] = 'application/x-www-form-urlencoded'; }
  const r = await fetch(url, opt), j = await r.json();
  if (!r.ok) throw new Error(j.error?.message || 'Stripe error');
  return j;
}
async function verifyStripe(env, raw, header) {
  const parts = Object.fromEntries((header || '').split(',').map(p => p.split('=')).filter(p => p.length === 2));
  const sigs = (header || '').split(',').filter(p => p.startsWith('v1=')).map(p => p.slice(3));
  if (!parts.t || !sigs.length) return false;
  if (Math.abs(Date.now() / 1000 - +parts.t) > 300) return false;
  const expect = hex(await hmac(env.STRIPE_WEBHOOK_SECRET, `${parts.t}.${raw}`));
  return sigs.some(s => safeEq(s, expect));
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

/* ---------- credits ---------- */
// Idempotent: the same ref can never grant twice (one transaction).
async function grant(env, userId, credits, reason, ref) {
  if (credits <= 0) return;
  await env.DB.batch([
    env.DB.prepare('UPDATE users SET credits=credits+?1 WHERE id=?2 AND NOT EXISTS(SELECT 1 FROM ledger WHERE ref=?3)').bind(credits, userId, ref),
    env.DB.prepare('INSERT OR IGNORE INTO ledger(user_id,delta,reason,ref,created_at) VALUES(?1,?2,?3,?4,?5)').bind(userId, credits, reason, ref, Date.now())
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
  return {
    id: u.id, email: u.email, name: u.name, credits: u.credits,
    sub: u.stripe_sub ? { status: u.sub_status, cancelAtPeriodEnd: !!u.sub_cancel } : null,
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

  if (credits > 0) {
    const r = await env.DB.batch([
      env.DB.prepare('UPDATE users SET credits=credits-?1 WHERE id=?2 AND credits>=?1').bind(credits, u.id),
      env.DB.prepare('INSERT INTO ledger(user_id,delta,reason,ref,created_at) SELECT ?1,?2,?3,?4,?5 WHERE changes()>0').bind(u.id, -credits, 'session', 's:' + sid, Date.now())
    ]);
    if (!r[0].meta.changes) fail(402, `You need ${credits} credits for this session.`);
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
    await grant(env, u.id, credits, 'refund', 'r:' + sid);       // give the credits back
    fail(502, e.name === 'TimeoutError' ? 'The device didn’t respond. You weren’t charged.' : e.message + ' You weren’t charged.');
  }
  const stmts = [env.DB.prepare('INSERT INTO sessions(id,user_id,device_id,credits,earned_cents,started_at) VALUES(?,?,?,?,?,?)').bind(sid, u.id, dev.id, credits, earned, Date.now())];
  if (earned > 0) stmts.push(env.DB.prepare('INSERT INTO earnings(user_id,cents,created_at) VALUES(?,?,?)').bind(dev.owner_id, earned, Date.now()));
  await env.DB.batch(stmts);
  const bal = await env.DB.prepare('SELECT credits FROM users WHERE id=?').bind(u.id).first();
  return { token: out.token, secondsLeft: out.secondsLeft, credits: bal.credits, spent: credits };
}

async function webhook(req, env) {
  const raw = await req.text();
  if (!(await verifyStripe(env, raw, req.headers.get('Stripe-Signature')))) fail(400, 'Bad signature');
  const ev = JSON.parse(raw), o = ev.data.object, { cc } = conf(env);
  const byCustomer = id => env.DB.prepare('SELECT * FROM users WHERE stripe_customer=?').bind(id).first();
  const subOf = i => i.subscription || i.parent?.subscription_details?.subscription || null;

  switch (ev.type) {
    case 'checkout.session.completed':
      if (o.mode === 'payment' && o.metadata?.kind === 'credits' && o.payment_status === 'paid')
        await grant(env, o.metadata.userId, num(o.metadata.credits, 0), 'purchase', 'cs:' + o.id);
      break;
    case 'invoice.paid': {            // every monthly payment becomes credits
      if (!subOf(o) || !o.amount_paid) break;
      const u = await byCustomer(o.customer);
      if (u) await grant(env, u.id, Math.floor(o.amount_paid / cc), 'subscription', 'inv:' + o.id);
      break;
    }
    case 'invoice.upcoming': {        // keep the plan priced at the highest device price
      const sid = subOf(o); if (!sid) break;
      const cents = await planCents(env), sub = await stripe(env, 'GET', '/subscriptions/' + sid), item = sub.items.data[0];
      if (item.price.unit_amount !== cents)
        await stripe(env, 'POST', '/subscriptions/' + sid, {
          proration_behavior: 'none',
          items: [{ id: item.id, price_data: { currency: 'usd', unit_amount: cents, product: env.STRIPE_PRODUCT_ID, recurring: { interval: 'month' } } }]
        });
      break;
    }
    case 'customer.subscription.created':
    case 'customer.subscription.updated':
      await env.DB.prepare('UPDATE users SET stripe_sub=?,sub_status=?,sub_cancel=? WHERE stripe_customer=?').bind(o.id, o.status, o.cancel_at_period_end ? 1 : 0, o.customer).run();
      break;
    case 'customer.subscription.deleted':
      await env.DB.prepare('UPDATE users SET stripe_sub=NULL,sub_status=NULL,sub_cancel=0 WHERE stripe_customer=?').bind(o.customer).run();
      break;
  }
  return { received: true };
}

async function route(req, env, url) {
  const p = url.pathname, m = req.method;
  const { cc, fee, hold, minPayout } = conf(env);

  if (m === 'GET' && p === '/config') {
    const cents = await planCents(env);
    return { creditCents: cc, packs: PACKS.map(c => ({ cents: c, credits: c / cc })), plan: { cents, credits: cents / cc }, holdDays: hold, minPayoutCents: minPayout, feePercent: fee };
  }
  if (m === 'POST' && p === '/auth/signup') {
    const b = await readJson(req), email = String(b.email || '').trim().toLowerCase(), name = String(b.name || '').trim().slice(0, 30), pw = String(b.password || '');
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) fail(400, 'Enter a valid email address.');
    if (!name) fail(400, 'Enter a display name.');
    if (pw.length < 8 || pw.length > 200) fail(400, 'Use a password of at least 8 characters.');
    if (await env.DB.prepare('SELECT 1 x FROM users WHERE email=?').bind(email).first()) fail(409, 'That email already has an account. Sign in instead.');
    const id = crypto.randomUUID(), salt = randHex(16);
    await env.DB.prepare('INSERT INTO users(id,email,name,pw_hash,pw_salt,created_at) VALUES(?,?,?,?,?,?)').bind(id, email, name, await hashPw(pw, salt), salt, Date.now()).run();
    return { token: await signToken(env, id) };
  }
  if (m === 'POST' && p === '/auth/login') {
    const b = await readJson(req), u = await env.DB.prepare('SELECT * FROM users WHERE email=?').bind(String(b.email || '').trim().toLowerCase()).first();
    const h = await hashPw(String(b.password || ''), u ? u.pw_salt : '00'.repeat(16));
    if (!u || !safeEq(h, u.pw_hash)) fail(401, 'Wrong email or password.');
    return { token: await signToken(env, u.id) };
  }
  if (m === 'GET' && p === '/devices') {
    const r = await env.DB.prepare('SELECT d.id,d.api_url,u.name volunteer FROM devices d JOIN users u ON u.id=d.owner_id ORDER BY d.created_at').all();
    return { devices: r.results.map(d => ({ id: d.id, apiUrl: d.api_url, volunteer: d.volunteer })) };
  }
  if (p === '/stripe/webhook' && m === 'POST') return webhook(req, env);

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
      line_items: [{ quantity: 1, price_data: { currency: 'usd', unit_amount: cents, product: env.STRIPE_PRODUCT_ID, recurring: { interval: 'month' } } }],
      subscription_data: { metadata: { userId: u.id } }, metadata: { kind: 'subscription', userId: u.id }
    });
    return { url: s.url };
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

async function cron(env) {
  const { results } = await env.DB.prepare('SELECT id,api_url FROM devices ORDER BY checked_at LIMIT 40').all();
  await Promise.all(results.map(async d => {
    const i = await piInfo(d.api_url), now = Date.now();
    if (i && i.online) await env.DB.prepare('UPDATE devices SET online=1,price_cents=?,last_seen=?,checked_at=? WHERE id=?').bind(Math.round((+i.price || 0) * 100), now, now, d.id).run();
    else await env.DB.prepare('UPDATE devices SET online=0,checked_at=? WHERE id=?').bind(now, d.id).run();
  }));
  if (new Date().getUTCHours() === 3) {
    const us = await env.DB.prepare('SELECT * FROM users WHERE connect_ready=1').all();
    for (const u of us.results) await payoutUser(env, u);
  }
}

export default {
  async fetch(req, env) {
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors(env) });
    try { return json(env, await route(req, env, new URL(req.url))); }
    catch (e) {
      if (e instanceof HttpError) return json(env, { error: e.message }, e.status);
      console.error(e); return json(env, { error: 'Something went wrong on our side.' }, 500);
    }
  },
  scheduled(_ev, env, ctx) { ctx.waitUntil(cron(env)); }
};
