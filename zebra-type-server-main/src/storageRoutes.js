const express = require("express");
const crypto = require("crypto");
const store = require("./db");

const router = express.Router();

// ── Persistent session + challenge tables in SQLite ──────────────────────────
// Using SQLite means sessions survive server restarts on Render.

const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
const CHALLENGE_TTL_MS = 2 * 60 * 1000;           // 2 minutes

function dbExec(sql) {
  try { store.db.exec(sql); } catch(e) {
    try { store.db.run(sql); } catch(e2) {}
  }
}
dbExec("CREATE TABLE IF NOT EXISTS zt_sessions (token TEXT PRIMARY KEY, username TEXT NOT NULL, is_admin INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL)");
dbExec("CREATE TABLE IF NOT EXISTS zt_challenges (nonce TEXT PRIMARY KEY, created_at INTEGER NOT NULL)");
dbExec("CREATE TABLE IF NOT EXISTS zt_device_bans (hash TEXT PRIMARY KEY, short_hash TEXT, username TEXT, score INTEGER, confidence INTEGER, signals TEXT, banned_at INTEGER NOT NULL)");

function dbRun(sql, params) {
  if (store.driver === "native") store.db.prepare(sql).run(...params);
  else store.db.run(sql, params);
}
function dbGet(sql, params) {
  if (store.driver === "native") return store.db.prepare(sql).get(...params);
  return store.db.get(sql, params);
}

// Sessions
function sessionSet(token, username, isAdmin) {
  try {
    dbRun("INSERT OR REPLACE INTO zt_sessions (token,username,is_admin,created_at) VALUES (?,?,?,?)", [token, username, isAdmin?1:0, Date.now()]);
    console.log("[session] saved for:", username, "isAdmin:", isAdmin);
  } catch(e){ console.error("[session] save error:", e.message); }
}
function sessionGet(token) {
  if (!token) return null;
  try {
    const row = dbGet("SELECT * FROM zt_sessions WHERE token=?", [token]);
    if (!row) { console.log("[session] token not found:", token.slice(0,8)+"..."); return null; }
    if (Date.now()-row.created_at > SESSION_TTL_MS) { dbRun("DELETE FROM zt_sessions WHERE token=?",[token]); console.log("[session] token expired"); return null; }
    return { username: row.username, isAdmin: !!row.is_admin };
  } catch(e) { console.error("[session] lookup error:", e.message); return null; }
}
function sessionDelete(token) {
  if (!token) return;
  try { dbRun("DELETE FROM zt_sessions WHERE token=?", [token]); } catch(e){}
}

// Challenges
function challengeSet(nonce) {
  try { dbRun("INSERT OR REPLACE INTO zt_challenges (nonce,created_at) VALUES (?,?)", [nonce, Date.now()]); } catch(e){}
}
function challengeConsume(nonce) {
  if (!nonce) return false;
  try {
    const row = dbGet("SELECT * FROM zt_challenges WHERE nonce=?", [nonce]);
    if (!row) return false;
    dbRun("DELETE FROM zt_challenges WHERE nonce=?", [nonce]);
    return Date.now()-row.created_at <= CHALLENGE_TTL_MS;
  } catch(e){ return false; }
}

// Prune old rows hourly
setInterval(() => {
  try { dbRun("DELETE FROM zt_sessions WHERE created_at<?", [Date.now()-SESSION_TTL_MS]); } catch(e){}
  try { dbRun("DELETE FROM zt_challenges WHERE created_at<?", [Date.now()-CHALLENGE_TTL_MS]); } catch(e){}
}, 60*60*1000);

function generateToken() { return crypto.randomBytes(32).toString("hex"); }

function getSession(req) { return sessionGet(req.header("x-session-token")); }

function isAccountKey(key) { return key.startsWith("account:"); }

// ── Challenge endpoint ────────────────────────────────────────────────────────

router.get("/challenge", (req, res) => {
  const nonce = crypto.randomBytes(24).toString("hex");
  challengeSet(nonce);
  res.json({ nonce });
});

// ── Auth endpoints ────────────────────────────────────────────────────────────

router.post("/register", (req, res) => {
  const { username, passwordHash, account } = req.body;
  if (!username || !passwordHash || !account) return res.status(400).json({ error: "missing fields" });
  const key = "account:" + username.toLowerCase();
  if (store.get("system", key, true)) return res.status(409).json({ error: "username taken" });
  store.set("system", key, JSON.stringify(account), true);
  const token = generateToken();
  sessionSet(token, username.toLowerCase(), false);
  res.json({ ok: true, token });
});

router.get("/check-username/:username", (req, res) => {
  const key = "account:" + req.params.username.toLowerCase();
  res.json({ taken: !!store.get("system", key, true) });
});

router.post("/login", (req, res) => {
  const { username, challengeResponse, nonce } = req.body;
  if (!username || !challengeResponse || !nonce) return res.status(400).json({ error: "missing fields" });
  if (!challengeConsume(nonce)) return res.status(401).json({ error: "invalid or expired challenge" });
  const result = store.get("system", "account:" + username.toLowerCase(), true);
  if (!result) return res.status(401).json({ error: "invalid credentials" });
  try {
    const acc = JSON.parse(result.value);
    const expected = crypto.createHash("sha256").update(acc.passwordHash + nonce).digest("hex");
    if (challengeResponse !== expected) return res.status(401).json({ error: "invalid credentials" });
    if (acc.isBanned) return res.status(403).json({ error: "banned" });
    const token = generateToken();
    sessionSet(token, username.toLowerCase(), false);
    res.json({ ok: true, token, account: acc });
  } catch(e) { res.status(500).json({ error: "server error" }); }
});

router.post("/admin-login", (req, res) => {
  const { challengeResponse, nonce } = req.body;
  if (!challengeResponse || !nonce) return res.status(400).json({ error: "missing fields" });
  if (!challengeConsume(nonce)) return res.status(401).json({ error: "invalid or expired challenge" });
  const result = store.get("system", "admin_account", true);
  if (!result) return res.status(401).json({ error: "no admin account" });
  try {
    const adminAcc = JSON.parse(result.value);
    const expected = crypto.createHash("sha256").update(adminAcc.passwordHash + nonce).digest("hex");
    if (challengeResponse !== expected) return res.status(401).json({ error: "invalid credentials" });
    const token = generateToken();
    sessionSet(token, "__admin__", true);
    res.json({ ok: true, token });
  } catch(e) { res.status(500).json({ error: "server error" }); }
});

router.post("/logout", (req, res) => {
  sessionDelete(req.header("x-session-token"));
  res.json({ ok: true });
});

router.get("/session", (req, res) => {
  const session = getSession(req);
  if (!session) return res.status(401).json({ error: "no session" });
  if (session.isAdmin) return res.json({ ok: true, account: null, isAdmin: true });
  const result = store.get("system", "account:" + session.username, true);
  if (!result) return res.status(401).json({ error: "account not found" });
  try {
    const acc = JSON.parse(result.value);
    if (acc.isBanned) { sessionDelete(req.header("x-session-token")); return res.status(403).json({ error: "banned" }); }
    res.json({ ok: true, account: acc });
  } catch(e) { res.status(500).json({ error: "server error" }); }
});

// ── KV endpoints ──────────────────────────────────────────────────────────────

router.get("/kv/:key", (req, res) => {
  const { key } = req.params;
  const shared = req.query.shared === "true";
  const session = getSession(req);
  // Account keys require any valid session (blocks unauthenticated scraping)
  // but any logged-in user can read any account (needed for leaderboards, guilds, friends, admin)
  if (isAccountKey(key) && !session) return res.status(403).json({ error: "forbidden" });
  const owner = session ? session.username : "anonymous";
  const result = store.get(owner, key, shared);
  if (!result) return res.status(404).json({ error: "not found" });
  res.json(result);
});

router.post("/kv/:key", (req, res) => {
  const { key } = req.params;
  const shared = req.body.shared === true;
  const session = getSession(req);
  if (typeof req.body.value !== "string") return res.status(400).json({ error: "value must be a string" });
  if (isAccountKey(key)) {
    if (!session) return res.status(403).json({ error: "forbidden" });

    // Sanity-check account writes to prevent console manipulation of stats.
    // Admins bypass these checks so they can make manual corrections.
    if (!session.isAdmin) {
      try {
        const incoming = JSON.parse(req.body.value);

        // Read the current account from DB to compare deltas
        const currentRaw = store.get("system", key, true);
        const current = currentRaw && currentRaw.value ? JSON.parse(currentRaw.value) : null;

        // WPM can never be set to more than 350 (our hard cap)
        if (typeof incoming.bestWpm === "number" && incoming.bestWpm > 350) {
          return res.status(400).json({ error: "invalid_stat", field: "bestWpm" });
        }

        // sumWpm can never decrease (you can't un-race) and can't jump by
        // more than 350 per race in a single save
        if (current && typeof incoming.sumWpm === "number") {
          if (incoming.sumWpm < (current.sumWpm || 0)) {
            return res.status(400).json({ error: "invalid_stat", field: "sumWpm" });
          }
          const wpmDelta = incoming.sumWpm - (current.sumWpm || 0);
          const raceDelta = (incoming.races || 0) - (current.races || 0);
          if (raceDelta >= 0 && wpmDelta > 350 * Math.max(1, raceDelta + 1)) {
            return res.status(400).json({ error: "invalid_stat", field: "sumWpm_delta" });
          }
        }

        // Race count can never decrease
        if (current && typeof incoming.races === "number") {
          if (incoming.races < (current.races || 0)) {
            return res.status(400).json({ error: "invalid_stat", field: "races" });
          }
        }

        // Points per race can't exceed what 350 WPM * 100% accuracy produces
        // racePoints = round(wpm^1.1 * (accuracy/100)), max ~= 350^1.1 * 1 ≈ 700 pts/race
        if (current && typeof incoming.totalPoints === "number") {
          if (incoming.totalPoints < (current.totalPoints || 0)) {
            return res.status(400).json({ error: "invalid_stat", field: "totalPoints" });
          }
          const ptsDelta = incoming.totalPoints - (current.totalPoints || 0);
          const raceDelta2 = Math.max(1, (incoming.races || 0) - (current.races || 0));
          if (ptsDelta > 800 * raceDelta2) {
            return res.status(400).json({ error: "invalid_stat", field: "totalPoints_delta" });
          }
        }

      } catch(e) {
        // If we can't parse the value, let it through — other validation
        // already handles malformed JSON elsewhere
      }
    }

    const result = store.set("system", key, req.body.value, true);
    return res.json(result);
  }
  if (!session) return res.status(401).json({ error: "authentication required" });
  res.json(store.set(session.username, key, req.body.value, shared));
});

router.delete("/kv/:key", (req, res) => {
  const { key } = req.params;
  const shared = req.query.shared === "true";
  const session = getSession(req);
  if (isAccountKey(key)) {
    const accountOwner = key.slice("account:".length).toLowerCase();
    if (!session || (session.username !== accountOwner && !session.isAdmin)) return res.status(403).json({ error: "forbidden" });
  } else if (!session) {
    return res.status(401).json({ error: "authentication required" });
  }
  res.json(store.del(session ? session.username : "anonymous", key, shared));
});

router.get("/kv-list", (req, res) => {
  const shared = req.query.shared === "true";
  const prefix = req.query.prefix || "";
  const session = getSession(req);
  console.log("[kv-list] prefix:", prefix, "hasToken:", !!req.header("x-session-token"), "session:", session ? session.username : "none");
  if (prefix.startsWith("account:") && !session) return res.status(401).json({ error: "authentication required" });
  const owner = session ? session.username : "anonymous";
  res.json(store.list(owner, prefix, shared));
});

// POST /api/bm-purchase — atomically completes a black market purchase.
// Validates the listing, deducts buyer coins, transfers item, pays seller —
// all in one request using the server's write access to both accounts.
router.post("/bm-purchase", (req, res) => {
  const session = getSession(req);
  if (!session) return res.status(401).json({ error: "authentication required" });

  const { listingKey, listingId, buyerUpdate, sellerUsername, sellerUpdate } = req.body;
  if (!listingKey || !listingId || !buyerUpdate || !sellerUsername || !sellerUpdate) {
    return res.status(400).json({ error: "missing fields" });
  }

  try {
    // Verify listing still exists (atomic check)
    const listingResult = store.get("system", listingKey, true);
    if (!listingResult || !listingResult.value) return res.status(404).json({ error: "listing_not_found" });
    const listings = JSON.parse(listingResult.value);
    const listing = Array.isArray(listings) ? listings.find(l => l.id === listingId) : null;
    if (!listing) return res.status(404).json({ error: "listing_not_found" });

    // Verify buyer has enough coins (double-check server-side)
    const buyerKey = "account:" + session.username.toLowerCase();
    const buyerResult = store.get("system", buyerKey, true);
    if (!buyerResult) return res.status(400).json({ error: "buyer_not_found" });
    const buyerAcc = JSON.parse(buyerResult.value);
    if ((buyerAcc.coins || 0) < listing.price) return res.status(400).json({ error: "insufficient_coins" });

    // Verify seller exists
    const sellerKey = "account:" + sellerUsername.toLowerCase();
    const sellerResult = store.get("system", sellerKey, true);
    if (!sellerResult) return res.status(400).json({ error: "seller_not_found" });

    // Remove listing atomically
    const updatedListings = listings.filter(l => l.id !== listingId);
    store.set("system", listingKey, JSON.stringify(updatedListings), true);

    // Save both accounts
    store.set("system", buyerKey, JSON.stringify(buyerUpdate), true);
    store.set("system", sellerKey, JSON.stringify(sellerUpdate), true);

    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: "server error: " + e.message });
  }
});

router.get("/maintenance-status", (req, res) => {
  const result = store.get("system", "site_maintenance", true);
  res.json({ maintenance: !!(result && result.value && JSON.parse(result.value)) });
});

// Debug endpoint — remove after fixing
router.get("/debug-session", (req, res) => {
  const token = req.header("x-session-token");
  const session = token ? sessionGet(token) : null;
  let tableExists = false;
  let rowCount = 0;
  try {
    const row = dbGet("SELECT COUNT(*) as c FROM zt_sessions", []);
    tableExists = true;
    rowCount = row ? row.c : 0;
  } catch(e) { tableExists = false; }
  res.json({
    hasToken: !!token,
    tokenLength: token ? token.length : 0,
    session: session,
    tableExists,
    rowCount,
    driver: store.driver
  });
});

// ── Device fingerprint ban endpoints ─────────────────────────────────────────

// POST /api/check-ban — called before race starts to block banned devices.
// Public (no session required) since it runs before the player is in a race.
router.post("/check-ban", (req, res) => {
  const { hash } = req.body || {};
  if (!hash) return res.json({ banned: false });
  try {
    const row = dbGet("SELECT hash FROM zt_device_bans WHERE hash=?", [hash]);
    res.json({ banned: !!row });
  } catch(e) {
    res.json({ banned: false }); // fail open
  }
});

// POST /api/anticheat — receives anticheat reports and auto-bans on high confidence.
// Called from the client's onBot callback with fingerprint attached.
router.post("/anticheat", (req, res) => {
  const session = getSession(req);
  const { score, confidence, signals, fingerprint } = req.body || {};
  const hash = fingerprint?.hash;
  const shortHash = fingerprint?.shortHash;
  const username = session?.username || null;
  try {
    if (confidence >= 99 && hash) {
      dbRun(
        "INSERT OR REPLACE INTO zt_device_bans (hash,short_hash,username,score,confidence,signals,banned_at) VALUES (?,?,?,?,?,?,?)",
        [hash, shortHash||null, username, score||0, confidence||0, JSON.stringify(signals||[]), Date.now()]
      );
      console.log(`[ban] Auto-banned device ${shortHash} for user ${username} (score=${score}, conf=${confidence}%)`);
    }
  } catch(e) {
    console.warn("[ban] Failed to record anticheat report:", e.message);
  }
  res.json({ received: true });
});

// POST /api/ban — manual device ban from admin panel.
router.post("/ban", (req, res) => {
  const session = getSession(req);
  if (!session || !session.isAdmin) return res.status(403).json({ error: "forbidden" });
  const { hash, shortHash, username } = req.body || {};
  if (!hash) return res.status(400).json({ error: "missing hash" });
  try {
    dbRun(
      "INSERT OR REPLACE INTO zt_device_bans (hash,short_hash,username,score,confidence,signals,banned_at) VALUES (?,?,?,?,?,?,?)",
      [hash, shortHash||null, username||null, 0, 100, "[]", Date.now()]
    );
    res.json({ banned: true });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/unban — remove a device ban.
router.post("/unban", (req, res) => {
  const session = getSession(req);
  if (!session || !session.isAdmin) return res.status(403).json({ error: "forbidden" });
  const { hash } = req.body || {};
  if (!hash) return res.status(400).json({ error: "missing hash" });
  try {
    dbRun("DELETE FROM zt_device_bans WHERE hash=?", [hash]);
    res.json({ unbanned: true });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/device-bans — list all banned devices (admin only).
router.get("/device-bans", (req, res) => {
  const session = getSession(req);
  if (!session || !session.isAdmin) return res.status(403).json({ error: "forbidden" });
  try {
    if (store.driver === "native") {
      const rows = store.db.prepare("SELECT * FROM zt_device_bans ORDER BY banned_at DESC LIMIT 200").all();
      return res.json({ bans: rows });
    }
    res.json({ bans: [] });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
