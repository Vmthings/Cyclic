# Cyclic
Powered by Cyclix.
Cyclic is an open source Android Phone session. Think about appetize.io, but with real phones, not the cloud.
# Cyclic server (Cloudflare Worker)

Holds what a static GitHub Pages site can't: accounts, credit balances, Stripe payments and volunteer payouts.
Volunteers still host their own Raspberry Pi. A Pi only starts a session when this server asks it to
(using that device's secret), after it has taken the user's credits.

## How the money moves
1. A user buys credits (one-off pack) or subscribes. The subscription costs the **highest device price** on Cyclic
   each month, and every payment becomes credits (1 credit = `CREDIT_CENTS`, default 10¢).
2. The user starts a session. The server takes the credits and tells the volunteer's Pi to start.
   If the Pi fails, the credits are refunded automatically.
3. The credits' value (minus `FEE_PERCENT`) is added to the volunteer's earnings.
4. After `HOLD_DAYS` (default 7), earnings are paid to the volunteer's bank by a Stripe Connect transfer,
   automatically each day at 03:00 UTC once they reach `MIN_PAYOUT_CENTS`, or when they press "Pay out now".

The hold period and the "you can't rent your own device" rule exist to stop someone buying credits with a stolen
card, renting their own phone and cashing out.

## Set up
```bash
cd worker
npm i -g wrangler && wrangler login
wrangler d1 create cyclic                      # copy the database_id into wrangler.toml
wrangler d1 execute cyclic --remote --file=schema.sql
```
Edit `wrangler.toml`: `SITE_ORIGIN`, `SITE_URL`, `STRIPE_PRODUCT_ID`, and the fee/hold settings.

**Stripe** (use test mode first):
1. Create a product called "Cyclic subscription" and put its id in `STRIPE_PRODUCT_ID`.
2. Turn on **Connect** and use Express accounts. If your volunteers are in other countries, check Stripe's
   cross-border payout rules for your region.
3. Add a webhook endpoint `https://YOUR-WORKER.workers.dev/stripe/webhook` with these events:
   `checkout.session.completed`, `invoice.paid`, `invoice.upcoming`,
   `customer.subscription.created`, `customer.subscription.updated`, `customer.subscription.deleted`.
4. Turn on the Customer portal (Billing → Customer portal) so subscribers can cancel.

```bash
wrangler secret put STRIPE_SECRET_KEY
wrangler secret put STRIPE_WEBHOOK_SECRET
wrangler secret put AUTH_SECRET                # any long random string
wrangler deploy
```
Finally open `index.html` and set `API_URL` to your Worker address (no trailing slash), then upload the site.

## Things to decide before going live
- **Stripe fees** (about 2.9% + 30¢ per payment) come out of your platform balance, not the volunteer's share, unless you set `FEE_PERCENT` to cover them.
- **Chargebacks:** if a buyer disputes a payment after spending the credits, you carry that loss. Credits aren't clawed back automatically.
- **Refund and credit-expiry rules:** the site doesn't state any. Decide them and add them to the shop text.
- **Rules for holding customers' money and paying others:** holding prepaid balances and paying third parties can bring licensing, tax-reporting and terms-of-service duties that depend on where you and your volunteers are. Check these (and Stripe Connect's terms) before launch.
- **Abuse protection:** add a Cloudflare rate-limiting rule for `/auth/*`. Passwords are hashed with PBKDF2, but there's no lockout.
- Subscription repricing happens when Stripe sends `invoice.upcoming` (about 3 days before renewal). The first month uses the highest price at sign-up.
- The hourly job checks up to 40 devices per run. Beyond that, raise the limit (and use a paid Workers plan).
