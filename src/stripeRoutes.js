const express = require("express");
const store = require("./db");

const router = express.Router();

// Your Premium Pass monthly subscription price, from the Stripe dashboard
// (Product catalog -> Premium Pass -> the recurring monthly price).
const PREMIUM_PRICE_ID = "price_1TpXcvDkfpMWyCeG6WF0jh5p";

// A SEPARATE, ONE-TIME price for gifting a year of premium to another
// player. This must be a "one time" price in Stripe (not recurring) --
// gifting is a single charge to the gifter, and the recipient gets a
// fixed year of premium with nothing auto-renewing. Set GIFT_PRICE_ID in
// the environment (Render) rather than hard-coding it, so it can be
// swapped without a code change.
const GIFT_PRICE_ID = process.env.GIFT_PRICE_ID || null;

// How long a gifted premium lasts. One year.
const GIFT_DURATION_MS = 365 * 24 * 60 * 60 * 1000;

// Stripe client is created lazily (not at module load) so a missing or
// not-yet-configured STRIPE_SECRET_KEY doesn't crash the whole server at
// boot -- it just makes these two routes return a clear error instead.
function getStripe() {
  if (!process.env.STRIPE_SECRET_KEY) return null;
  return require("stripe")(process.env.STRIPE_SECRET_KEY);
}

// Minimal session lookup, matching storageRoutes.js's own session helpers.
// Duplicated here (rather than imported) so this file has no dependency
// on storageRoutes.js's internals -- it only needs read access to the
// shared "system" KV store, same as storageRoutes.js does.
async function getSession(req) {
  const token = req.header("x-session-token");
  if (!token) return null;
  try {
    const result = await store.get("system", "session_" + token, true);
    if (!result || !result.value) return null;
    const row = JSON.parse(result.value);
    return { username: row.username, isAdmin: !!row.isAdmin };
  } catch (e) { return null; }
}

// ── Start a subscription checkout ──────────────────────────────────────────
router.post("/create-checkout-session", async (req, res) => {
  const stripe = getStripe();
  if (!stripe) return res.status(500).json({ error: "stripe_not_configured" });

  const session = await getSession(req);
  if (!session || session.isAdmin) return res.status(401).json({ error: "authentication required" });

  try {
    const accountKey = "account:" + session.username;
    const accResult = await store.get("system", accountKey, true);
    if (!accResult || !accResult.value) return res.status(404).json({ error: "account_not_found" });
    const acc = JSON.parse(accResult.value);

    if (acc.hasPremiumPass) return res.status(400).json({ error: "already_premium" });

    const origin = req.headers.origin || (req.protocol + "://" + req.get("host"));

    function buildParams(customerId) {
      return {
        mode: "subscription",
        line_items: [{ price: PREMIUM_PRICE_ID, quantity: 1 }],
        // client_reference_id is how the webhook knows which player account
        // this checkout belongs to once payment completes.
        client_reference_id: session.username,
        customer: customerId || undefined,
        metadata: { username: session.username },
        success_url: origin + "/account?premium=success",
        cancel_url: origin + "/account?premium=cancelled"
      };
    }

    let checkoutSession;
    try {
      checkoutSession = await stripe.checkout.sessions.create(buildParams(acc.stripeCustomerId));
    } catch (e) {
      // A saved customer ID can point at a different Stripe mode than
      // whichever key the server is currently using (e.g. a customer
      // created during test-mode testing, then the server switched to
      // live keys) -- Stripe rejects that as "No such customer" rather
      // than silently ignoring it. Rather than fail the purchase, drop
      // the stale ID from the account and let Stripe create a fresh
      // customer instead -- this makes the flow self-healing instead of
      // needing a manual data fix every time this happens.
      const isStaleCustomer = e.message && e.message.indexOf("No such customer") !== -1;
      if (isStaleCustomer && acc.stripeCustomerId) {
        console.warn("[stripe] dropping stale customer id for", session.username, "-", acc.stripeCustomerId);
        delete acc.stripeCustomerId;
        delete acc.stripeSubscriptionId;
        await store.set("system", accountKey, JSON.stringify(acc), true);
        checkoutSession = await stripe.checkout.sessions.create(buildParams(null));
      } else {
        throw e;
      }
    }

    res.json({ url: checkoutSession.url });
  } catch (e) {
    console.error("[stripe] create-checkout-session error:", e.message);
    res.status(500).json({ error: "stripe_error", message: e.message });
  }
});

// ── Gift a year of premium to another player (one-time charge) ──────────────
router.post("/create-gift-checkout-session", async (req, res) => {
  const stripe = getStripe();
  if (!stripe) return res.status(500).json({ error: "stripe_not_configured" });
  if (!GIFT_PRICE_ID) return res.status(500).json({ error: "gift_not_configured" });

  const session = await getSession(req);
  if (!session || session.isAdmin) return res.status(401).json({ error: "authentication required" });

  const recipientRaw = (req.body && req.body.recipient) ? String(req.body.recipient) : "";
  const recipient = recipientRaw.trim().toLowerCase();
  if (!recipient) return res.status(400).json({ error: "missing_recipient" });

  // Can't gift to yourself -- that's just buying premium, which the normal
  // flow already handles.
  if (recipient === session.username.toLowerCase()) {
    return res.status(400).json({ error: "cannot_gift_self" });
  }

  try {
    // Verify the recipient exists and isn't already premium. Re-checking
    // server-side matters -- the client hides the button for premium users,
    // but a crafted request could still try, and we don't want someone
    // paying for a gift that does nothing.
    const recipientResult = await store.get("system", "account:" + recipient, true);
    if (!recipientResult || !recipientResult.value) {
      return res.status(404).json({ error: "recipient_not_found" });
    }
    const recipientAcc = JSON.parse(recipientResult.value);
    if (recipientAcc.hasPremiumPass) {
      return res.status(400).json({ error: "recipient_already_premium" });
    }

    const origin = req.headers.origin || (req.protocol + "://" + req.get("host"));
    const recipientDisplay = recipientAcc.username || recipient;

    const checkoutSession = await stripe.checkout.sessions.create({
      // One-time payment, NOT a subscription -- no recurring charge, no
      // customer mapping created, nothing to renew or tangle.
      mode: "payment",
      line_items: [{ price: GIFT_PRICE_ID, quantity: 1 }],
      // The webhook reads these to know who to grant premium to (the
      // recipient) and who paid (the gifter, for logging).
      metadata: {
        gift: "true",
        recipient: recipient,
        gifter: session.username,
      },
      success_url: origin + "/racer/" + encodeURIComponent(recipientDisplay) + "?gift=success",
      cancel_url: origin + "/racer/" + encodeURIComponent(recipientDisplay) + "?gift=cancelled",
    });

    res.json({ url: checkoutSession.url });
  } catch (e) {
    console.error("[stripe] create-gift-checkout-session error:", e.message);
    res.status(500).json({ error: "stripe_error", message: e.message });
  }
});

// ── Manage/cancel an existing subscription ─────────────────────────────────
// Requires the Customer Portal to be turned on once in the Stripe dashboard
// (Settings -> Billing -> Customer portal) before this will work.
router.post("/create-billing-portal-session", async (req, res) => {
  const stripe = getStripe();
  if (!stripe) return res.status(500).json({ error: "stripe_not_configured" });

  const session = await getSession(req);
  if (!session || session.isAdmin) return res.status(401).json({ error: "authentication required" });

  try {
    const accountKey = "account:" + session.username;
    const accResult = await store.get("system", accountKey, true);
    if (!accResult || !accResult.value) return res.status(404).json({ error: "account_not_found" });
    const acc = JSON.parse(accResult.value);
    if (!acc.stripeCustomerId) return res.status(400).json({ error: "no_subscription" });

    const origin = req.headers.origin || (req.protocol + "://" + req.get("host"));
    let portalSession;
    try {
      portalSession = await stripe.billingPortal.sessions.create({
        customer: acc.stripeCustomerId,
        return_url: origin + "/account"
      });
    } catch (e) {
      const isStaleCustomer = e.message && e.message.indexOf("No such customer") !== -1;
      if (isStaleCustomer) {
        // Same cross-mode staleness as create-checkout-session -- there's
        // no live subscription to manage if the saved customer doesn't
        // exist in the mode currently in use, so clear it and report
        // "no subscription" rather than a raw Stripe error.
        console.warn("[stripe] dropping stale customer id for", session.username, "-", acc.stripeCustomerId);
        delete acc.stripeCustomerId;
        delete acc.stripeSubscriptionId;
        await store.set("system", accountKey, JSON.stringify(acc), true);
        return res.status(400).json({ error: "no_subscription" });
      }
      throw e;
    }

    res.json({ url: portalSession.url });
  } catch (e) {
    console.error("[stripe] create-billing-portal-session error:", e.message);
    res.status(500).json({ error: "stripe_error", message: e.message });
  }
});

module.exports = router;
