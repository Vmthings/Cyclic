# Cyclic

A static site (GitHub Pages) where volunteers lend Android phones through a Raspberry Pi. There is no separate server:
**VmThings hosts the Cyclic "server" from their own browser**, and everyone else connects to it over WebRTC.

```
index.html            the site
host/config.js        VmThings pastes the public host key here
host/core.js          the server logic (accounts, credits, Stripe, payouts)
host/host.js          runs the host in the browser: database, host key, connections
host/client.js        what visitors use to reach the host (and verify it's the real one)
host/hostui.js        the "Host (VmThings only)" dialog
host/vendor/          sql.js (database) and PeerJS (WebRTC), copied here so no CDN is needed
pi-agent/             what each volunteer runs on their Raspberry Pi
```

## How it fits together
- **Accounts:** stored in a database on VmThings' device. A visitor's browser keeps only a signed sign-in token in a cookie (30 days, limited to this site's path). Balances aren't kept in cookies, because anyone could edit them.
- **Only VmThings can host:** hosting needs a private key that lives only on VmThings' device, encrypted with the host password. Visitors check a signature against the public key in `host/config.js`, so nobody else can pretend to be the host, even if they claim the same connection ID. The `VmThings` name is reserved.
- **Credits:** 1 credit = 10¢. When someone starts a session, the host takes the credits and tells the volunteer's Pi to start. The value of those credits becomes the volunteer's earnings. After 7 days it's paid to their bank through Stripe Connect.
- **Subscription:** costs the highest device price each month (minimum $5) and turns into credits. The price follows the highest device price before each renewal.
- **Cyclic Enterprise:** a team plan. The buyer enters how many people they have. The monthly price is **the highest device price × people + $10**. The $10 flat fee goes to VmThings and is not turned into credits. The rest becomes credits in the buyer's account, shared with the team: the buyer gets an invite code, up to that many people can join, and their sessions are paid from the shared credits first. The buyer can remove people, rotate the code and see a 30-day usage report. Cancelling ends the team (the buyer keeps their credits). The Account section shows VmThings the total of fees collected.
- **Perks:** every active subscription gets (a) bonus credits each month (Monthly +5%, Enterprise +10%), (b) full session history (everyone else sees the latest 3), and (c) a Member / Enterprise badge. Enterprise adds the shared credit pool and team tools. People on an Enterprise team get the perks too while the plan is active. **The bonus credits are paid for by the host:** when they're spent, volunteers are still paid in full, so the bonus comes out of your Stripe balance. Set the percentages to 0 in `host/host.js` to turn that perk off.
- **Stripe without a server:** there is no webhook. The host reads Stripe's recent events every minute while it's open, so a payment made while the host is offline is still credited when the host next opens (Stripe keeps events for 30 days).

## VmThings: first-time setup
1. Upload this folder to your GitHub Pages repo.
2. In **Stripe**, make a **restricted key** (test mode first) with write access to: Checkout Sessions, Customers, Customer portal sessions, Subscriptions, Products, Accounts, Account Links, Transfers; and read access to Events and Invoices. Turn on **Connect** (Express accounts) and the **Customer portal**.
3. Open the site on your own computer and click **Host (VmThings only)** at the bottom. Enter your email, a strong password and the Stripe key, then **Set up and start hosting**.
4. The dialog shows a line starting `export const HOST_PUBLIC_KEY = …`. Paste it over the matching line in `host/config.js` and upload that file. Until you do, visitors see the host as unverified/offline.
5. **Download both backups** (key and database) and keep them somewhere safe. If you lose the key you can't host again without changing `config.js`; if you lose the database you lose every balance.
6. To host later, open the site, click Host, enter the password and press **Start hosting**.

**Keep the tab open.** When it closes, the host is offline: nobody can sign in, buy credits or start a session. Visitors see a banner and the site retries automatically. Use a computer that stays on, and avoid a browser setting that puts background tabs to sleep.

## Volunteers
Follow the steps on the site (Volunteer section). In the Pi's `config.json`, set `allowedOrigin` to the site's address, because the host's browser calls the Pi directly.

## Things to know
- **Your Stripe key is in a browser.** It's encrypted at rest with your password, but while hosting it's in memory in a page that runs this site's code. Use a **restricted** key, keep the site's files yours alone, don't install risky browser extensions on that browser, and start in test mode.
- **WebRTC needs the PeerJS public broker** (free, no guarantees). Some networks block direct connections without a TURN server; add one in `host/config.js` (`PEER_OPTIONS`) if visitors can't connect.
- **Settings** (credit value, fee, hold days, minimum payout, minimum plan price, perk bonuses, the Enterprise $10 fee) are the `DEFAULTS` in `host/host.js`.
- **Keep the Enterprise fees in your balance.** The $10 per team stays in your Stripe balance along with everything else. The Account section shows the running total, so you know how much of the balance is yours before you pay volunteers.
- Holding customers' credits and paying volunteers may carry licensing, tax and terms-of-service duties depending on where you are. Stripe fees, chargebacks, refunds and credit expiry are yours to decide and state on the site.
