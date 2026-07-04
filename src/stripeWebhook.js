const store = require("./db");

function getStripe() {
  if (!process.env.STRIPE_SECRET_KEY) return null;
  return require("stripe")(process.env.STRIPE_SECRET_KEY);
}

// Grants (or renews) premium on a player's account, and remembers which
// Stripe customer maps to which username -- future webhook events (renewal,
// cancellation) only carry the Stripe customer/subscription IDs, not the
// username, so this reverse-lookup is what lets us find the right account
// later without having to search every account in the database.
async function grantPremiumToUsername(username, expiresAtMs, stripeCustomerId, stripeSubscriptionId) {
  const key = "account:" + username.toLowerCase();
  const result = await store.get("system", key, true);
  if (!result || !result.value) {
    console.warn("[stripe webhook] no account found for username:", username);
    return;
  }
  const acc = JSON.parse(result.value);
  acc.hasPremiumPass = true;
  acc.premiumExpiresAt = expiresAtMs;
  if (stripeCustomerId) acc.stripeCustomerId = stripeCustomerId;
  if (stripeSubscriptionId) acc.stripeSubscriptionId = stripeSubscriptionId;
  await store.set("system", key, JSON.stringify(acc), true);

  if (stripeCustomerId) {
    await store.set("system", "stripe_customer_" + stripeCustomerId, username.toLowerCase(), true);
  }
  console.log("[stripe webhook] premium granted:", username, "until", new Date(expiresAtMs).toISOString());
}

async function revokePremiumForCustomer(stripeCustomerId) {
  const mapResult = await store.get("system", "stripe_customer_" + stripeCustomerId, true);
  if (!mapResult || !mapResult.value) {
    console.warn("[stripe webhook] no username mapped for customer:", stripeCustomerId);
    return;
  }
  const username = mapResult.value;
  const key = "account:" + username;
  const result = await store.get("system", key, true);
  if (!result || !result.value) return;
  const acc = JSON.parse(result.value);
  acc.hasPremiumPass = false;
  acc.premiumExpiresAt = null;
  await store.set("system", key, JSON.stringify(acc), true);
  console.log("[stripe webhook] premium revoked:", username);
}

// IMPORTANT: this handler must receive the RAW (unparsed) request body --
// see server.js, where this route is registered before the global
// express.json() middleware for exactly that reason. Signature
// verification below fails on a body that's already been JSON-parsed.
async function handleStripeWebhook(req, res) {
  const stripe = getStripe();
  if (!stripe) return res.status(500).send("stripe not configured");

  const sig = req.headers["stripe-signature"];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    // Signature didn't match -- this request did not actually come from
    // Stripe (or the webhook secret is misconfigured). Reject it outright;
    // never process an unverified event, since that's how someone could
    // grant themselves free premium by forging a fake request.
    console.error("[stripe webhook] signature verification failed:", err.message);
    return res.status(400).send("Webhook Error: " + err.message);
  }

  try {
    switch (event.type) {
      case "checkout.session.completed": {
        const session = event.data.object;
        const username = session.client_reference_id || (session.metadata && session.metadata.username);
        if (username && session.subscription) {
          const sub = await stripe.subscriptions.retrieve(session.subscription);
          await grantPremiumToUsername(username, sub.current_period_end * 1000, session.customer, sub.id);
        }
        break;
      }

      case "customer.subscription.updated": {
        const sub = event.data.object;
        if (sub.status === "active" || sub.status === "trialing") {
          const mapResult = await store.get("system", "stripe_customer_" + sub.customer, true);
          if (mapResult && mapResult.value) {
            await grantPremiumToUsername(mapResult.value, sub.current_period_end * 1000, sub.customer, sub.id);
          }
        } else if (sub.status === "canceled" || sub.status === "unpaid" || sub.status === "past_due") {
          await revokePremiumForCustomer(sub.customer);
        }
        break;
      }

      case "customer.subscription.deleted": {
        const sub = event.data.object;
        await revokePremiumForCustomer(sub.customer);
        break;
      }

      case "invoice.payment_succeeded": {
        // Fires on renewal each billing cycle -- extend the expiry.
        const invoice = event.data.object;
        if (invoice.subscription) {
          const sub = await stripe.subscriptions.retrieve(invoice.subscription);
          const mapResult = await store.get("system", "stripe_customer_" + sub.customer, true);
          if (mapResult && mapResult.value) {
            await grantPremiumToUsername(mapResult.value, sub.current_period_end * 1000, sub.customer, sub.id);
          }
        }
        break;
      }

      default:
        // Ignore anything else Stripe sends us.
        break;
    }
    res.json({ received: true });
  } catch (e) {
    console.error("[stripe webhook] handler error:", e.message);
    // Return 500 so Stripe retries this event automatically rather than
    // silently losing a payment update.
    res.status(500).json({ error: "handler_error" });
  }
}

module.exports = { handleStripeWebhook };
