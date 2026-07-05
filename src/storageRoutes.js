const express = require("express");
const crypto = require("crypto");
const store = require("./db");

const router = express.Router();

const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
const CHALLENGE_TTL_MS = 2 * 60 * 1000;         // 2 minutes

// ── MongoDB Session + Challenge Helpers ──────────────────────────

async function sessionSet(token, username, isAdmin) {
  try {
    const data = JSON.stringify({ username, isAdmin: isAdmin ? 1 : 0, created_at: Date.now() });
    await store.set("system", "session_" + token, data, true);
    console.log("[session] saved for:", username, "isAdmin:", isAdmin);
  } catch (e) { console.error("[session] save error:", e.message); }
}

async function sessionGet(token) {
  if (!token) return null;
  try {
    const result = await store.get("system", "session_" + token, true);
    if (!result || !result.value) return null;
    
    const row = JSON.parse(result.value);
    if (Date.now() - row.created_at > SESSION_TTL_MS) { 
        await store.del("system", "session_" + token, true); 
        return null; 
    }
    return { username: row.username, isAdmin: !!row.isAdmin };
  } catch (e) { console.error("[session] lookup error:", e.message); return null; }
}

async function sessionDelete(token) {
  if (!token) return;
  try { await store.del("system", "session_" + token, true); } catch (e) {}
}

async function challengeSet(nonce) {
  try { 
      const data = JSON.stringify({ created_at: Date.now() });
      await store.set("system", "challenge_" + nonce, data, true); 
  } catch (e) {}
}

async function challengeConsume(nonce) {
  if (!nonce) return false;
  try {
    const result = await store.get("system", "challenge_" + nonce, true);
    if (!result || !result.value) return false;
    
    await store.del("system", "challenge_" + nonce, true);
    const row = JSON.parse(result.value);
    return Date.now() - row.created_at <= CHALLENGE_TTL_MS;
  } catch (e) { return false; }
}

function generateToken() { return crypto.randomBytes(32).toString("hex"); }

async function getSession(req) { return await sessionGet(req.header("x-session-token")); }

async function isIpBanned(ip) {
  if (!ip) return false;
  try {
    const result = await store.get("system", "ipban_" + ip, true);
    return !!(result && result.value);
  } catch (e) { return false; }
}

function isAccountKey(key) { return key.startsWith("account:"); }

// ── Challenge endpoint ────────────────────────────────────────────────────────

router.get("/challenge", async (req, res) => {
  const nonce = crypto.randomBytes(24).toString("hex");
  await challengeSet(nonce);
  res.json({ nonce });
});

// ── Auth endpoints ────────────────────────────────────────────────────────────

router.post("/register", async (req, res) => {
  const { username, passwordHash, account } = req.body;
  if (!username || !passwordHash || !account) return res.status(400).json({ error: "missing fields" });

  const clientIp = req.ip;
  if (await isIpBanned(clientIp)) return res.status(403).json({ error: "ip_banned" });

  const key = "account:" + username.toLowerCase();
  const existing = await store.get("system", key, true);
  if (existing) return res.status(409).json({ error: "username taken" });

  account.lastKnownIp = clientIp;
  await store.set("system", key, JSON.stringify(account), true);
  const token = generateToken();
  await sessionSet(token, username.toLowerCase(), false);
  res.json({ ok: true, token });
});

router.get("/check-username/:username", async (req, res) => {
  const key = "account:" + req.params.username.toLowerCase();
  const existing = await store.get("system", key, true);
  res.json({ taken: !!existing });
});

router.post("/login", async (req, res) => {
  const { username, challengeResponse, nonce } = req.body;
  if (!username || !challengeResponse || !nonce) return res.status(400).json({ error: "missing fields" });

  const clientIp = req.ip;
  if (await isIpBanned(clientIp)) return res.status(403).json({ error: "ip_banned" });

  const validChallenge = await challengeConsume(nonce);
  if (!validChallenge) return res.status(401).json({ error: "invalid or expired challenge" });
  
  const result = await store.get("system", "account:" + username.toLowerCase(), true);
  if (!result || !result.value) return res.status(401).json({ error: "invalid credentials" });
  
  try {
    const acc = JSON.parse(result.value);
    const expected = crypto.createHash("sha256").update(acc.passwordHash + nonce).digest("hex");
    if (challengeResponse !== expected) return res.status(401).json({ error: "invalid credentials" });
    if (acc.isBanned) return res.status(403).json({ error: acc.bannedViaIp ? "ip_banned" : "banned" });

    acc.lastKnownIp = clientIp;
    await store.set("system", "account:" + username.toLowerCase(), JSON.stringify(acc), true);

    const token = generateToken();
    await sessionSet(token, username.toLowerCase(), false);
    res.json({ ok: true, token, account: acc });
  } catch (e) { res.status(500).json({ error: "server error" }); }
});

router.post("/admin-login", async (req, res) => {
  const { challengeResponse, nonce } = req.body;
  if (!challengeResponse || !nonce) return res.status(400).json({ error: "missing fields" });
  
  const validChallenge = await challengeConsume(nonce);
  if (!validChallenge) return res.status(401).json({ error: "invalid or expired challenge" });
  
  const result = await store.get("system", "admin_account", true);
  if (!result || !result.value) return res.status(401).json({ error: "no admin account" });
  
  try {
    const adminAcc = JSON.parse(result.value);
    const expected = crypto.createHash("sha256").update(adminAcc.passwordHash + nonce).digest("hex");
    if (challengeResponse !== expected) return res.status(401).json({ error: "invalid credentials" });
    
    const token = generateToken();
    await sessionSet(token, "__admin__", true);
    res.json({ ok: true, token });
  } catch (e) { res.status(500).json({ error: "server error" }); }
});

router.post("/logout", async (req, res) => {
  await sessionDelete(req.header("x-session-token"));
  res.json({ ok: true });
});

router.get("/session", async (req, res) => {
  const session = await getSession(req);
  if (!session) return res.status(401).json({ error: "no session" });
  if (session.isAdmin) return res.json({ ok: true, account: null, isAdmin: true });

  if (await isIpBanned(req.ip)) {
    await sessionDelete(req.header("x-session-token"));
    return res.status(403).json({ error: "ip_banned" });
  }

  const result = await store.get("system", "account:" + session.username, true);
  if (!result || !result.value) return res.status(401).json({ error: "account not found" });
  
  try {
    const acc = JSON.parse(result.value);
    if (acc.isBanned) { 
        await sessionDelete(req.header("x-session-token")); 
        return res.status(403).json({ error: acc.bannedViaIp ? "ip_banned" : "banned" }); 
    }
    res.json({ ok: true, account: acc });
  } catch (e) { res.status(500).json({ error: "server error" }); }
});

// ── KV endpoints ──────────────────────────────────────────────────────────────

router.get("/kv/:key", async (req, res) => {
  const { key } = req.params;
  const shared = req.query.shared === "true";
  const session = await getSession(req);
  
  if (isAccountKey(key) && !session) return res.status(403).json({ error: "forbidden" });
  const owner = session ? session.username : "anonymous";
  
  const result = await store.get(owner, key, shared);
  if (!result) return res.status(404).json({ error: "not found" });
  res.json(result);
});

router.post("/kv/:key", async (req, res) => {
  const { key } = req.params;
  const shared = req.body.shared === true;
  const session = await getSession(req);
  
  if (typeof req.body.value !== "string") return res.status(400).json({ error: "value must be a string" });
  
  if (isAccountKey(key)) {
    if (!session) return res.status(403).json({ error: "forbidden" });

    if (!session.isAdmin) {
      try {
        const incoming = JSON.parse(req.body.value);
        const currentRaw = await store.get("system", key, true);
        const current = currentRaw && currentRaw.value ? JSON.parse(currentRaw.value) : null;

        if (typeof incoming.bestWpm === "number" && incoming.bestWpm > 350) return res.status(400).json({ error: "invalid_stat", field: "bestWpm" });
        if (current && typeof incoming.sumWpm === "number") {
          if (incoming.sumWpm < (current.sumWpm || 0)) return res.status(400).json({ error: "invalid_stat", field: "sumWpm" });
          const wpmDelta = incoming.sumWpm - (current.sumWpm || 0);
          const raceDelta = (incoming.races || 0) - (current.races || 0);
          if (raceDelta >= 0 && wpmDelta > 350 * Math.max(1, raceDelta + 1)) return res.status(400).json({ error: "invalid_stat", field: "sumWpm_delta" });
        }
        if (current && typeof incoming.races === "number") {
          if (incoming.races < (current.races || 0)) return res.status(400).json({ error: "invalid_stat", field: "races" });
        }
        if (current && typeof incoming.totalPoints === "number") {
          if (incoming.totalPoints < (current.totalPoints || 0)) return res.status(400).json({ error: "invalid_stat", field: "totalPoints" });
          const ptsDelta = incoming.totalPoints - (current.totalPoints || 0);
          const raceDelta2 = Math.max(1, (incoming.races || 0) - (current.races || 0));
          if (ptsDelta > 800 * raceDelta2) return res.status(400).json({ error: "invalid_stat", field: "totalPoints_delta" });
        }
      } catch (e) {}
    }

    const result = await store.set("system", key, req.body.value, true);
    return res.json(result);
  }
  
  // Special case: the one-time super-admin account claim. This has to be
  // reachable with NO session at all, since claiming it is what happens
  // before any session exists in the first place -- it's a separate
  // login system from regular player accounts, not something a player
  // session gates. Once an admin account already exists, only someone
  // already authenticated AS that admin may overwrite it (e.g. changing
  // the admin password later) -- a random unauthenticated request must
  // never be able to hijack an already-claimed admin account.
  if (key === "admin_account" && shared) {
    const existingAdmin = await store.get("system", key, true);
    if (existingAdmin) {
      if (!session || !session.isAdmin) return res.status(403).json({ error: "forbidden" });
    }
    const result = await store.set("system", key, req.body.value, true);
    return res.json(result);
  }

  if (!session) return res.status(401).json({ error: "authentication required" });
  res.json(await store.set(session.username, key, req.body.value, shared));
});

router.delete("/kv/:key", async (req, res) => {
  const { key } = req.params;
  const shared = req.query.shared === "true";
  const session = await getSession(req);
  
  if (isAccountKey(key)) {
    const accountOwner = key.slice("account:".length).toLowerCase();
    if (!session || (session.username !== accountOwner && !session.isAdmin)) return res.status(403).json({ error: "forbidden" });
  } else if (!session) {
    return res.status(401).json({ error: "authentication required" });
  }
  res.json(await store.del(session ? session.username : "anonymous", key, shared));
});

router.get("/kv-list", async (req, res) => {
  const shared = req.query.shared === "true";
  const prefix = req.query.prefix || "";
  const session = await getSession(req);
  
  if (prefix.startsWith("account:") && !session) return res.status(401).json({ error: "authentication required" });
  const owner = session ? session.username : "anonymous";
  res.json(await store.list(owner, prefix, shared));
});

router.post("/bm-purchase", async (req, res) => {
  const session = await getSession(req);
  if (!session) return res.status(401).json({ error: "authentication required" });

  const { listingKey, listingId, buyerUpdate, sellerUsername, sellerUpdate } = req.body;
  if (!listingKey || !listingId || !buyerUpdate || !sellerUsername || !sellerUpdate) {
    return res.status(400).json({ error: "missing fields" });
  }

  try {
    const listingResult = await store.get("system", listingKey, true);
    if (!listingResult || !listingResult.value) return res.status(404).json({ error: "listing_not_found" });
    const listings = JSON.parse(listingResult.value);
    const listing = Array.isArray(listings) ? listings.find(l => l.id === listingId) : null;
    if (!listing) return res.status(404).json({ error: "listing_not_found" });

    const buyerKey = "account:" + session.username.toLowerCase();
    const buyerResult = await store.get("system", buyerKey, true);
    if (!buyerResult) return res.status(400).json({ error: "buyer_not_found" });
    const buyerAcc = JSON.parse(buyerResult.value);
    if ((buyerAcc.coins || 0) < listing.price) return res.status(400).json({ error: "insufficient_coins" });

    const sellerKey = "account:" + sellerUsername.toLowerCase();
    const sellerResult = await store.get("system", sellerKey, true);
    if (!sellerResult) return res.status(400).json({ error: "seller_not_found" });

    const updatedListings = listings.filter(l => l.id !== listingId);
    await store.set("system", listingKey, JSON.stringify(updatedListings), true);
    await store.set("system", buyerKey, JSON.stringify(buyerUpdate), true);
    await store.set("system", sellerKey, JSON.stringify(sellerUpdate), true);

    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: "server error: " + e.message }); }
});

router.get("/maintenance-status", async (req, res) => {
  try {
      const result = await store.get("system", "site_maintenance", true);
      res.json({ maintenance: !!(result && result.value && JSON.parse(result.value)) });
  } catch (e) { res.json({ maintenance: false }); }
});

// Debug endpoint 
router.get("/debug-session", async (req, res) => {
  const token = req.header("x-session-token");
  const session = token ? await sessionGet(token) : null;
  res.json({ hasToken: !!token, tokenLength: token ? token.length : 0, session: session, driver: store.driver });
});

// ── Device fingerprint ban endpoints ─────────────────────────────────────────

router.post("/check-ban", async (req, res) => {
  const { hash } = req.body || {};
  if (!hash) return res.json({ banned: false });
  try {
    const result = await store.get("system", "ban_" + hash, true);
    res.json({ banned: !!(result && result.value) });
  } catch (e) { res.json({ banned: false }); }
});

router.post("/anticheat", async (req, res) => {
  const session = await getSession(req);
  const { score, confidence, signals, fingerprint } = req.body || {};
  const hash = fingerprint?.hash;
  const username = session?.username || null;
  try {
    if (confidence >= 99 && hash) {
      const data = JSON.stringify({ short_hash: fingerprint?.shortHash, username, score, confidence, signals, banned_at: Date.now() });
      await store.set("system", "ban_" + hash, data, true);
    }
  } catch (e) {}
  res.json({ received: true });
});

router.post("/ban", async (req, res) => {
  const session = await getSession(req);
  if (!session || !session.isAdmin) return res.status(403).json({ error: "forbidden" });
  const { hash, shortHash, username } = req.body || {};
  if (!hash) return res.status(400).json({ error: "missing hash" });
  try {
    const data = JSON.stringify({ short_hash: shortHash, username, score: 0, confidence: 100, signals: [], banned_at: Date.now() });
    await store.set("system", "ban_" + hash, data, true);
    res.json({ banned: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

router.post("/unban", async (req, res) => {
  const session = await getSession(req);
  if (!session || !session.isAdmin) return res.status(403).json({ error: "forbidden" });
  const { hash } = req.body || {};
  if (!hash) return res.status(400).json({ error: "missing hash" });
  try {
    await store.del("system", "ban_" + hash, true);
    res.json({ unbanned: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

router.get("/device-bans", async (req, res) => {
  const session = await getSession(req);
  if (!session || !session.isAdmin) return res.status(403).json({ error: "forbidden" });
  try {
    const rawList = await store.list("system", "ban_", true);
    const bans = rawList.map(item => JSON.parse(item.value));
    res.json({ bans });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── IP ban endpoints ──────────────────────────────────────────────────────────
// Separate from the device-fingerprint ban system above -- an IP ban blocks
// a network address regardless of which account or device is used from it,
// which is coarser than fingerprinting (easy to change via VPN/mobile data,
// and can catch other people sharing the same network) but useful as an
// extra layer alongside it.

router.post("/ip-ban", async (req, res) => {
  const session = await getSession(req);
  if (!session || !session.isAdmin) return res.status(403).json({ error: "forbidden" });
  const { ip, username } = req.body || {};
  if (!ip) return res.status(400).json({ error: "missing ip" });
  try {
    const data = JSON.stringify({ ip, username: username || null, banned_at: Date.now() });
    await store.set("system", "ipban_" + ip, data, true);
    res.json({ banned: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

router.post("/ip-unban", async (req, res) => {
  const session = await getSession(req);
  if (!session || !session.isAdmin) return res.status(403).json({ error: "forbidden" });
  const { ip } = req.body || {};
  if (!ip) return res.status(400).json({ error: "missing ip" });
  try {
    await store.del("system", "ipban_" + ip, true);
    res.json({ unbanned: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

router.get("/ip-bans", async (req, res) => {
  const session = await getSession(req);
  if (!session || !session.isAdmin) return res.status(403).json({ error: "forbidden" });
  try {
    const rawList = await store.list("system", "ipban_", true);
    const bans = rawList.map(item => JSON.parse(item.value));
    res.json({ bans });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Manually run the expired session/login-challenge cleanup right now,
// instead of waiting for the hourly scheduled run in server.js.
router.post("/admin/cleanup-auth-keys", async (req, res) => {
  const session = await getSession(req);
  if (!session || !session.isAdmin) return res.status(403).json({ error: "forbidden" });
  try {
    const result = await store.cleanupExpiredAuthKeys();
    res.json({ ok: true, ...result });
  } catch (e) {
    res.status(500).json({ error: "cleanup_failed", message: e.message });
  }
});

module.exports = router;
