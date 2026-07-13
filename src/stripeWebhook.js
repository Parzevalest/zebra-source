const store = require("./db");

function getStripe() {
  if (!process.env.STRIPE_SECRET_KEY) return null;
  return require("stripe")(process.env.STRIPE_SECRET_KEY);
}

// Stripe moved subscription billing periods off the top-level Subscription
// object and onto each subscription item individually (API version
// 2025-03-31 "basil" and later) -- sub.current_period_end no longer
// exists on current API versions. This reads it from the right place,
// while still falling back to the old top-level field just in case this
// ever runs against an older API version.
function getSubscriptionPeriodEnd(sub) {
  var itemPeriodEnd = sub.items && sub.items.data && sub.items.data[0] && sub.items.data[0].current_period_end;
  return itemPeriodEnd || sub.current_period_end || null;
}

// Stripe also moved the invoice-to-subscription link into a nested
// "parent" field on the same API version bump -- invoice.subscription no
// longer exists on current API versions either.
function getInvoiceSubscriptionId(invoice) {
  return (invoice.parent && invoice.parent.subscription_details && invoice.parent.subscription_details.subscription)
    || invoice.subscription
    || null;
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
  await revokePremiumForUsername(username, "subscription_ended");
}

// Revoke premium directly by username. Used by both the customer-mapping
// path and the chargeback/dispute path. `reason` is recorded on the account
// for admin visibility. If reason is a chargeback, also flags the account.
async function revokePremiumForUsername(username, reason) {
  if (!username) return;
  const key = "account:" + username.toLowerCase();
  const result = await store.get("system", key, true);
  if (!result || !result.value) return;
  const acc = JSON.parse(result.value);
  acc.hasPremiumPass = false;
  acc.premiumExpiresAt = null;

  // Mark chargeback abusers so you can see who disputed a charge and decide
  // whether to let them buy again. This does NOT auto-ban -- disputes can be
  // legitimate (a real unauthorized card) -- it just flags for your review.
  if (reason === "chargeback" || reason === "refund") {
    acc.chargebackFlag = true;
    acc.chargebackAt = Date.now();
    acc.chargebackReason = reason;
  }

  await store.set("system", key, JSON.stringify(acc), true);
  console.log("[stripe webhook] premium revoked:", username, "reason:", reason);
}

// Traces a disputed or refunded charge back to the account that received
// premium from it, and revokes. Two cases:
//   1. GIFT: we stored gift_pi_<paymentIntent> -> recipient at grant time.
//   2. SELF-PURCHASE: the charge's customer maps via stripe_customer_<id>.
// Tries the gift mapping first (gifts have no customer link), then falls
// back to the customer path.
async function revokeForCharge(stripe, chargeId, paymentIntentId, reason) {
  try {
    // Resolve the payment_intent if we only got a charge id.
    let piId = paymentIntentId;
    if (!piId && chargeId && stripe) {
      try {
        const charge = await stripe.charges.retrieve(chargeId);
        piId = charge.payment_intent || null;
      } catch (e) { /* fall through */ }
    }

    // Case 1: gift.
    if (piId) {
      const giftMap = await store.get("system", "gift_pi_" + piId, true);
      if (giftMap && giftMap.value) {
        await revokePremiumForUsername(giftMap.value, reason);
        console.log("[stripe webhook] gift premium revoked via", reason, "for recipient:", giftMap.value);
        return;
      }
    }

    // Case 2: self-purchase -- resolve the customer on the charge, then map.
    if (chargeId && stripe) {
      try {
        const charge = await stripe.charges.retrieve(chargeId);
        if (charge.customer) {
          await revokePremiumForCustomer(charge.customer);
          // revokePremiumForCustomer logs, but ensure the chargeback flag is
          // set too by re-revoking by username with the reason.
          const mapResult = await store.get("system", "stripe_customer_" + charge.customer, true);
          if (mapResult && mapResult.value) {
            await revokePremiumForUsername(mapResult.value, reason);
          }
          return;
        }
      } catch (e) {
        console.error("[stripe webhook] could not retrieve charge for revoke:", e.message);
      }
    }

    console.warn("[stripe webhook] chargeback/refund could not be traced to an account. charge:", chargeId, "pi:", piId);
  } catch (e) {
    console.error("[stripe webhook] revokeForCharge error:", e.message);
  }
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

        // Gift path: a one-time payment (no subscription) that grants the
        // RECIPIENT a fixed year of premium. Identified by the metadata we
        // set when creating the gift checkout. Handled before the normal
        // subscription path since a gift session has no subscription.
        if (session.metadata && session.metadata.gift === "true") {
          const recipient = session.metadata.recipient;
          const gifter = session.metadata.gifter || "unknown";
          if (recipient) {
            // One year from now. Deliberately NOT tied to a Stripe
            // customer/subscription -- nothing renews, so we don't create
            // a customer->username mapping (that mapping is only for
            // recurring subscriptions).
            const GIFT_DURATION_MS = 365 * 24 * 60 * 60 * 1000;
            const expiresAt = Date.now() + GIFT_DURATION_MS;
            await grantPremiumToUsername(recipient, expiresAt, null, null);

            // Record a payment-intent -> recipient mapping so that if the
            // gifter later disputes/refunds this one-time charge, we can
            // trace it back to the RECIPIENT and revoke their premium.
            // (Gifts have no customer mapping, so this is the only link.)
            if (session.payment_intent) {
              await store.set("system", "gift_pi_" + session.payment_intent, recipient.toLowerCase(), true);
            }

            console.log("[stripe webhook] GIFT premium granted to", recipient, "from", gifter, "until", new Date(expiresAt).toISOString());
          } else {
            console.error("[stripe webhook] gift session missing recipient metadata:", session.id);
          }
          break;
        }

        const username = session.client_reference_id || (session.metadata && session.metadata.username);
        if (username && session.subscription) {
          const sub = await stripe.subscriptions.retrieve(session.subscription);
          const periodEnd = getSubscriptionPeriodEnd(sub);
          if (periodEnd) {
            await grantPremiumToUsername(username, periodEnd * 1000, session.customer, sub.id);
          } else {
            console.error("[stripe webhook] could not determine period end for subscription:", sub.id);
          }
        }
        break;
      }

      case "customer.subscription.updated": {
        const sub = event.data.object;
        if (sub.status === "active" || sub.status === "trialing") {
          const mapResult = await store.get("system", "stripe_customer_" + sub.customer, true);
          if (mapResult && mapResult.value) {
            const periodEnd = getSubscriptionPeriodEnd(sub);
            if (periodEnd) {
              await grantPremiumToUsername(mapResult.value, periodEnd * 1000, sub.customer, sub.id);
            } else {
              console.error("[stripe webhook] could not determine period end for subscription:", sub.id);
            }
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

      // ── Chargeback / dispute: revoke premium immediately ──────────────────
      // A dispute means the cardholder told their bank to reverse the charge.
      // We revoke right away (per the chosen policy) so someone can't dispute
      // a charge and keep the perk. Works for both self-purchases (traced via
      // the customer mapping) and gifts (traced via the gift payment-intent
      // mapping we stored at grant time).
      case "charge.dispute.created": {
        const dispute = event.data.object;
        await revokeForCharge(stripe, dispute.charge, dispute.payment_intent, "chargeback");
        break;
      }

      // A refund (whether you issued it or Stripe did) should also pull the
      // perk back, otherwise a refunded user keeps premium for free.
      case "charge.refunded": {
        const charge = event.data.object;
        await revokeForCharge(stripe, charge.id, charge.payment_intent, "refund");
        break;
      }

      case "invoice.payment_succeeded": {
        // Fires on renewal each billing cycle -- extend the expiry.
        const invoice = event.data.object;
        const invoiceSubId = getInvoiceSubscriptionId(invoice);
        if (invoiceSubId) {
          const sub = await stripe.subscriptions.retrieve(invoiceSubId);
          const mapResult = await store.get("system", "stripe_customer_" + sub.customer, true);
          if (mapResult && mapResult.value) {
            const periodEnd = getSubscriptionPeriodEnd(sub);
            if (periodEnd) {
              await grantPremiumToUsername(mapResult.value, periodEnd * 1000, sub.customer, sub.id);
            } else {
              console.error("[stripe webhook] could not determine period end for subscription:", sub.id);
            }
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
