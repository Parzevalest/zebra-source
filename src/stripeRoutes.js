const express = require("express");
const store = require("./db");

const router = express.Router();

// Your Premium Pass monthly subscription price, from the Stripe dashboard
// (Product catalog -> Premium Pass -> the recurring monthly price).
const PREMIUM_PRICE_ID = "price_1TpWU4DkfpMWyCeGggNMaddU";

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

    const checkoutSession = await stripe.checkout.sessions.create({
      mode: "subscription",
      line_items: [{ price: PREMIUM_PRICE_ID, quantity: 1 }],
      // client_reference_id is how the webhook knows which player account
      // this checkout belongs to once payment completes.
      client_reference_id: session.username,
      customer: acc.stripeCustomerId || undefined,
      metadata: { username: session.username },
      success_url: origin + "/account?premium=success",
      cancel_url: origin + "/account?premium=cancelled"
    });

    res.json({ url: checkoutSession.url });
  } catch (e) {
    console.error("[stripe] create-checkout-session error:", e.message);
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
    const portalSession = await stripe.billingPortal.sessions.create({
      customer: acc.stripeCustomerId,
      return_url: origin + "/account"
    });

    res.json({ url: portalSession.url });
  } catch (e) {
    console.error("[stripe] create-billing-portal-session error:", e.message);
    res.status(500).json({ error: "stripe_error", message: e.message });
  }
});

module.exports = router;
