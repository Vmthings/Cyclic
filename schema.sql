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
