const express = require("express");
const crypto = require("crypto");
const store = require("./db");
const security = require("./security");

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

async function isFingerprintBanned(hash) {
  if (!hash) return false;
  try {
    const result = await store.get("system", "ban_" + hash, true);
    return !!(result && result.value);
  } catch (e) { return false; }
}

// Bans every account whose last-known IP matches the given address (used
// both when an admin manually IP-bans a player, and when the anticheat
// system auto-bans an IP). Returns how many additional accounts were
// newly banned as a result, so the caller can report that back.
async function cascadeBanAccountsForIp(ip) {
  const usernames = [];
  try {
    const matches = await store.findAccountsByLastKnownIp(ip);
    for (const row of matches) {
      try {
        const acc = JSON.parse(row.value);
        if (acc.isBanned) continue;
        acc.isBanned = true;
        acc.bannedViaIp = true;
        await store.set("system", row.key, JSON.stringify(acc), true);
        usernames.push(acc.username || row.key.replace(/^account:/, ""));
      } catch (e) { /* skip a malformed record rather than fail the whole batch */ }
    }
  } catch (e) {}
  return usernames;
}

function isAccountKey(key) { return key.startsWith("account:"); }

// A session counts as admin-or-moderator if it's the true super-admin
// session, OR the requesting player's OWN account has isModerator set.
// Moderator status lives on the account record, not the session token,
// so it has to be looked up fresh here rather than trusted from the
// session object alone.
async function isRequesterAdminOrModerator(session) {
  if (!session) return false;
  if (session.isAdmin) return true;
  try {
    const raw = await store.get("system", "account:" + session.username, true);
    if (raw && raw.value) return !!JSON.parse(raw.value).isModerator;
  } catch (e) {}
  return false;
}

// Shared game-content/configuration keys that only an admin or moderator
// should ever be able to write -- catalogs, wheel/season/streak setup,
// news, etc. Deliberately does NOT include keys regular players
// legitimately write themselves during normal play (black market
// listings, guild records, session/challenge/ban bookkeeping, the race
// activity log). Without this check, any authenticated player could
// rewrite wheel odds, season rewards, achievements, news posts, or any
// other catalog for the entire game just by POSTing to this route
// directly with a crafted key.
const ADMIN_ONLY_SHARED_KEYS = new Set([
  "custom_cars", "nametag_catalog", "avatar_catalog", "achievements_catalog",
  "wheel_prizes", "wheel_configs", "wheel_configs_backup",
  "title_catalog", "season_config", "season_config_backup",
  "race_tracks", "about_sections", "guild_lb_config",
  "news_posts", "streak_config", "streak_standard_pool", "streak_premium_pool",
  "race_passages", "site_maintenance", "tos_content", "anticheat_timing_flags",
]);

// ── Challenge endpoint ────────────────────────────────────────────────────────

router.get("/challenge", async (req, res) => {
  const nonce = crypto.randomBytes(24).toString("hex");
  await challengeSet(nonce);
  res.json({ nonce });
});

// ── Auth endpoints ────────────────────────────────────────────────────────────

router.post("/register", security.rateLimit({
  max: 40, windowMs: 60 * 60 * 1000, keyPrefix: "register",
  message: "Too many accounts created from this network recently. Please try again later.",
}), async (req, res) => {
  const { username, passwordHash, account, fingerprintHash } = req.body;
  if (!username || !passwordHash || !account) return res.status(400).json({ error: "missing fields" });

  const clientIp = req.ip;
  if (await isIpBanned(clientIp)) return res.status(403).json({ error: "ip_banned" });
  if (await isFingerprintBanned(fingerprintHash)) return res.status(403).json({ error: "device_banned" });

  const key = "account:" + username.toLowerCase();
  const existing = await store.get("system", key, true);
  if (existing) return res.status(409).json({ error: "username taken" });

  account.lastKnownIp = clientIp;
  account.lastLoginAt = Date.now();
  if (fingerprintHash) account.deviceFingerprint = fingerprintHash;
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

router.post("/login", security.rateLimit({
  max: 20, windowMs: 5 * 60 * 1000, keyPrefix: "login",
  message: "Too many login attempts. Please wait a few minutes and try again.",
}), async (req, res) => {
  const { username, challengeResponse, nonce, fingerprintHash } = req.body;
  if (!username || !challengeResponse || !nonce) return res.status(400).json({ error: "missing fields" });

  // Per-account brute-force lockout. Checked before doing any crypto work,
  // so a locked account short-circuits immediately. This defends a single
  // account's password even against an attacker rotating IPs (which the
  // per-IP rate limit above wouldn't catch on its own).
  const lock = security.checkAccountLock(username);
  if (lock.locked) {
    res.set("Retry-After", String(lock.retryAfterSec));
    return res.status(429).json({ error: "account_locked", message: "Too many failed attempts for this account. Try again in a few minutes." });
  }

  const clientIp = req.ip;
  if (await isFingerprintBanned(fingerprintHash)) return res.status(403).json({ error: "device_banned" });
  // IP-ban is deliberately NOT checked yet here -- see below. Checking it
  // only after the password is verified means a wrong-password attempt
  // against someone else's username from a banned IP can't be used to
  // fish for "is this IP banned?" or to get an innocent account marked
  // ip-banned by someone who doesn't even know its real password.

  const validChallenge = await challengeConsume(nonce);
  if (!validChallenge) return res.status(401).json({ error: "invalid or expired challenge" });
  
  const result = await store.get("system", "account:" + username.toLowerCase(), true);
  if (!result || !result.value) {
    // Count a login attempt against a nonexistent username too, so the
    // lockout can't be sidestepped by fishing usernames.
    security.recordFailedLogin(username);
    return res.status(401).json({ error: "invalid credentials" });
  }

  try {
    const acc = JSON.parse(result.value);
    const expected = crypto.createHash("sha256").update(acc.passwordHash + nonce).digest("hex");
    if (challengeResponse !== expected) {
      security.recordFailedLogin(username);
      return res.status(401).json({ error: "invalid credentials" });
    }

    // Correct password -- clear any accumulated failed-attempt counter.
    security.clearFailedLogins(username);

    // Credentials are verified at this point, so it's now safe to check
    // and act on IP-ban status. If this account isn't already banned but
    // is logging in from an IP that's already banned, mark it banned too
    // -- this is what makes the IP ban actually stick to every account
    // that uses it, not just the one it was originally issued for.
    if (!acc.isBanned && await isIpBanned(clientIp)) {
      acc.isBanned = true;
      acc.bannedViaIp = true;
    }
    if (acc.isBanned) {
      await store.set("system", "account:" + username.toLowerCase(), JSON.stringify(acc), true);
      return res.status(403).json({ error: acc.bannedViaIp ? "ip_banned" : "banned" });
    }

    acc.lastKnownIp = clientIp;
    acc.lastLoginAt = Date.now();
    // Note: acc.deviceFingerprint is intentionally NOT overwritten here --
    // that field is what "Ban Device" in the admin panel bans, and it's
    // meant to stay pinned to whichever device actually got flagged by the
    // anticheat system (see the anticheat report handler below), not
    // whatever device happens to log in most recently.
    await store.set("system", "account:" + username.toLowerCase(), JSON.stringify(acc), true);

    const token = generateToken();
    await sessionSet(token, username.toLowerCase(), false);
    res.json({ ok: true, token, account: acc });
  } catch (e) { res.status(500).json({ error: "server error" }); }
});

router.post("/admin-login", security.rateLimit({
  max: 10, windowMs: 10 * 60 * 1000, keyPrefix: "adminlogin",
  message: "Too many admin login attempts. Please wait several minutes.",
}), async (req, res) => {
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

  const result = await store.get("system", "account:" + session.username, true);
  if (!result || !result.value) return res.status(401).json({ error: "account not found" });

  try {
    const acc = JSON.parse(result.value);

    if (!acc.isBanned && await isIpBanned(req.ip)) {
      acc.isBanned = true;
      acc.bannedViaIp = true;
      await store.set("system", "account:" + session.username, JSON.stringify(acc), true);
    }
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

  // Reading another player's account is legitimate (public profiles,
  // leaderboards, guild pages all do this) -- but the raw record also
  // contains fields that must never be exposed to anyone but the owner
  // or an admin/moderator. passwordHash especially: this login scheme has
  // no per-account salt, so knowing the hash is functionally equivalent
  // to knowing the password itself for authentication purposes. IP and
  // device fingerprint are also private/security-sensitive, not
  // gameplay data. Redact these rather than blocking the read entirely,
  // since blocking it would break every feature that shows another
  // player's stats.
  if (isAccountKey(key)) {
    const accountOwner = key.slice("account:".length).toLowerCase();
    const isSelfRead = session && session.username === accountOwner;
    if (!isSelfRead) {
      const authorized = await isRequesterAdminOrModerator(session);
      if (!authorized) {
        try {
          const acc = JSON.parse(result.value);
          delete acc.passwordHash;
          delete acc.lastKnownIp;
          delete acc.deviceFingerprint;
          delete acc.deviceFingerprintShort;
          return res.json({ key: result.key, value: JSON.stringify(acc), shared: result.shared });
        } catch (e) { /* if it doesn't parse as JSON, fall through and return as-is */ }
      }
    }
  }

  res.json(result);
});

router.post("/kv/:key", async (req, res) => {
  const { key } = req.params;
  const shared = req.body.shared === true;
  const session = await getSession(req);
  
  if (typeof req.body.value !== "string") return res.status(400).json({ error: "value must be a string" });
  
  if (isAccountKey(key)) {
    if (!session) return res.status(403).json({ error: "forbidden" });

    // CRITICAL: a session may only write to another player's account if
    // it's an admin or moderator. Without this check, any authenticated
    // player could overwrite any OTHER player's whole account (coins,
    // premium status, owned items, ban status, even passwordHash) just by
    // POSTing to this route with a different account's key.
    const accountOwner = key.slice("account:".length).toLowerCase();
    const isSelfWrite = session.username === accountOwner;

    if (!isSelfWrite) {
      const authorized = await isRequesterAdminOrModerator(session);
      if (!authorized) return res.status(403).json({ error: "forbidden" });
    }

    // What actually gets written. For a player saving their OWN account this
    // becomes a merge of their save against the live database copy (see
    // reconcileAccountSelfWrite) rather than a blind overwrite. Admin and
    // moderator writes are stored verbatim -- they're deliberate edits to
    // another player's account, not a stale background save.
    let valueToStore = req.body.value;

    if (!session.isAdmin && isSelfWrite) {
      try {
        const incoming = JSON.parse(req.body.value);
        const currentRaw = await store.get("system", key, true);
        const current = currentRaw && currentRaw.value ? JSON.parse(currentRaw.value) : null;

        if (typeof incoming.bestWpm === "number" && incoming.bestWpm > 350) return res.status(400).json({ error: "invalid_stat", field: "bestWpm" });
        if (current && typeof incoming.sumWpm === "number") {
          if (incoming.sumWpm < (current.sumWpm || 0)) return res.status(400).json({ error: "invalid_stat", field: "sumWpm" });
          const wpmDelta = incoming.sumWpm - (current.sumWpm || 0);
          const raceDelta = (incoming.races || 0) - (current.races || 0);
          // A single race can contribute at most 350 to the sum (the same
          // ceiling bestWpm itself is capped at) -- the multiplier here
          // must be raceDelta, not raceDelta + 1, or a client claiming
          // exactly 1 new race could smuggle in up to 700 worth of sumWpm,
          // silently doubling their average WPM contribution per race.
          if (raceDelta >= 0 && wpmDelta > 350 * Math.max(1, raceDelta)) return res.status(400).json({ error: "invalid_stat", field: "sumWpm_delta" });
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

        // Merge rather than overwrite. Without this, a stale client copy
        // silently undoes anything another player changed on this account
        // (accepted friend requests, coins received, black-market sales).
        if (current) {
          valueToStore = JSON.stringify(
            reconcileAccountSelfWrite(incoming, current, req.body.baseline)
          );
        }
      } catch (e) { /* fall back to storing the value as sent */ }
    }

    const result = await store.set("system", key, valueToStore, true);
    // Hand the merged account back so the client can resync its own copy and
    // its baseline instead of continuing to work from a stale one.
    return res.json(Object.assign({}, result, { merged: valueToStore }));
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

  if (shared && ADMIN_ONLY_SHARED_KEYS.has(key)) {
    const authorized = await isRequesterAdminOrModerator(session);
    if (!authorized) return res.status(403).json({ error: "forbidden" });
  }

  if (!session) return res.status(401).json({ error: "authentication required" });
  const genericResult = await store.set(session.username, key, req.body.value, shared);
  // Invalidate the maintenance-status cache immediately on a deliberate
  // toggle, rather than letting up to MAINTENANCE_CACHE_MS pass before an
  // admin's own change to their own site actually takes effect.
  if (key === "site_maintenance") maintenanceStatusCache = { value: null, cachedAt: 0 };
  return res.json(genericResult);
});

router.delete("/kv/:key", async (req, res) => {
  const { key } = req.params;
  const shared = req.query.shared === "true";
  const session = await getSession(req);
  
  if (isAccountKey(key)) {
    const accountOwner = key.slice("account:".length).toLowerCase();
    if (!session) return res.status(403).json({ error: "forbidden" });
    if (session.username !== accountOwner) {
      const authorized = await isRequesterAdminOrModerator(session);
      if (!authorized) return res.status(403).json({ error: "forbidden" });
    }
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

// Note: an earlier "/bm-purchase" endpoint used to live here. It was never
// actually called by the client (the real black market purchase flow uses
// the generic /kv/ routes directly, with its own server-side ownership
// checks), and it trusted client-supplied buyerUpdate/sellerUpdate objects
// verbatim with no validation -- a real vulnerability with zero actual
// usage. Removed rather than hardened, since nothing depends on it.

// Cached briefly in memory so a burst of concurrent clients polling this
// (every open tab checks this repeatedly) doesn't each trigger a fresh
// database query for a value that only changes when an admin deliberately
// toggles maintenance mode -- effectively never, compared to how often
// this gets polled.
let maintenanceStatusCache = { value: null, cachedAt: 0 };
const MAINTENANCE_CACHE_MS = 5000;

router.get("/maintenance-status", async (req, res) => {
  try {
    const now = Date.now();
    if (maintenanceStatusCache.value !== null && (now - maintenanceStatusCache.cachedAt) < MAINTENANCE_CACHE_MS) {
      return res.json({ maintenance: maintenanceStatusCache.value });
    }
    const result = await store.get("system", "site_maintenance", true);
    const maintenance = !!(result && result.value && JSON.parse(result.value));
    maintenanceStatusCache = { value: maintenance, cachedAt: now };
    res.json({ maintenance });
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

      // Also ban the reporting IP itself, and cascade that ban to every
      // other account already known to share it -- a bot operator running
      // multiple accounts from the same machine/network gets all of them
      // shut down at once, not just the one that got caught this time.
      const reportIp = req.ip;
      if (reportIp) {
        const ipData = JSON.stringify({ ip: reportIp, username, banned_at: Date.now(), reason: "anticheat_auto_ban" });
        await store.set("system", "ipban_" + reportIp, ipData, true);
        const cascaded = await cascadeBanAccountsForIp(reportIp);
        if (cascaded.length) {
          console.log(`[anticheat] auto-banned IP ${reportIp} (triggered by ${username || "unknown"}) -- also banned: ${cascaded.join(", ")}`);
        }
      }
    }
  } catch (e) {}
  res.json({ received: true });
});

router.get("/timing-flags", async (req, res) => {
  const session = await getSession(req);
  if (!session || !session.isAdmin) return res.status(403).json({ error: "forbidden" });
  try {
    const row = await store.get("system", "anticheat_timing_flags", true);
    let flags = [];
    if (row && row.value) { try { flags = JSON.parse(row.value); } catch (e) { flags = []; } }
    if (!Array.isArray(flags)) flags = [];
    // Newest first for the admin view.
    flags.reverse();
    res.json({ flags });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

router.post("/timing-flags/clear", async (req, res) => {
  const session = await getSession(req);
  if (!session || !session.isAdmin) return res.status(403).json({ error: "forbidden" });
  try {
    await store.set("system", "anticheat_timing_flags", JSON.stringify([]), true);
    res.json({ cleared: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Cross-account operations (friends / coins / black market) ────────────────
//
// WHY THESE EXIST: a player may NOT write to another player's account -- see
// the ownership check on POST /kv/:key. That check is important (without it
// anyone could rewrite anyone's coins, items, premium, or ban status), but
// friend requests, coin transfers, and black-market purchases all inherently
// need to modify a SECOND player's account. They used to be done client-side,
// which meant the second write was rejected with 403 and the action silently
// half-applied -- a friend request that never arrived, coins that never sent,
// and a black-market purchase that charged the buyer while the seller kept
// their item (duplication). Performing them here, with server authority and
// server-side validation, is the correct fix.
//
// Everything below re-reads both accounts fresh from the database and never
// trusts client-supplied balances, quantities, or prices.

const AVATAR_SLOTS = ["shoes", "pants", "shirt", "head"];
const MIN_COINS_TO_SEND = 1000;

function sameUser(a, b) {
  return String(a || "").toLowerCase() === String(b || "").toLowerCase();
}

async function loadAccount(username) {
  if (!username || typeof username !== "string") return null;
  const raw = await store.get("system", "account:" + username.toLowerCase(), true);
  if (!raw || !raw.value) return null;
  try { return JSON.parse(raw.value); } catch (e) { return null; }
}

async function storeAccount(acc) {
  await store.set("system", "account:" + String(acc.username).toLowerCase(), JSON.stringify(acc), true);
}

// ── Reconciling a player's own account save ────────────────────────────────
//
// The client keeps the whole account object in memory and saves ALL of it
// (saveAccount -> POST /kv/account:me). That is a "last write wins" write,
// and it silently destroys changes that OTHER players legitimately made to
// this account while the client's copy was sitting stale in a browser tab:
//
//   * a friend accepts your request  -> your stale save re-adds it as pending
//   * someone sends you coins        -> your stale save deletes the coins
//   * someone buys your BM listing   -> your stale save restores the item
//                                       and removes the seller's payment
//
// Those were reported as three separate bugs; they are all this one.
//
// Fields ONLY the server ever changes. The client has no code path that
// assigns these (verified), so a self-write must never be allowed to set
// them -- we always take the database's copy instead.
const SERVER_OWNED_ACCOUNT_FIELDS = [
  "friendUsernames",
  "incomingFriendRequests",
  "outgoingFriendRequests",
  "pendingCoinNotifications",
];

// Contested fields are ones BOTH sides legitimately change: the player
// (race rewards, wheel spins, buying things) and other players (coin gifts,
// black-market sales). We can't take the client's value (that clobbers the
// other player) or the database's (that discards the player's own progress).
// So we apply the client's DELTA -- what it actually changed relative to the
// copy it originally loaded (the "baseline" it sends back) -- on top of the
// current database value.
//
// Note this is no easier to cheat than what it replaces: a client could
// already claim any coin total it liked. This only changes clobbering into
// merging.
function _num(v) { const n = Number(v); return Number.isFinite(n) ? n : 0; }

function reconcileNumber(dbVal, incomingVal, baseVal) {
  return _num(dbVal) + (_num(incomingVal) - _num(baseVal));
}

// For "do I own at least one" string lists (ownedCarIds, ownedNameTags...).
function reconcileStringList(dbList, incomingList, baseList) {
  const db = Array.isArray(dbList) ? dbList.slice() : [];
  const inc = Array.isArray(incomingList) ? incomingList : [];
  const base = Array.isArray(baseList) ? baseList : [];
  const removed = base.filter((x) => inc.indexOf(x) === -1);
  const out = db.filter((x) => removed.indexOf(x) === -1);
  inc.filter((x) => base.indexOf(x) === -1)
     .forEach((x) => { if (out.indexOf(x) === -1) out.push(x); });
  return out;
}

// For {id: count} quantity maps (carQuantities, avatarPieceQuantities[slot]).
function reconcileQtyMap(dbMap, incomingMap, baseMap) {
  const db = (dbMap && typeof dbMap === "object") ? Object.assign({}, dbMap) : {};
  const inc = (incomingMap && typeof incomingMap === "object") ? incomingMap : {};
  const base = (baseMap && typeof baseMap === "object") ? baseMap : {};
  const keys = new Set(Object.keys(inc).concat(Object.keys(base)));
  keys.forEach((k) => {
    const delta = _num(inc[k]) - _num(base[k]);
    if (delta === 0) return;
    const next = _num(db[k]) + delta;
    if (next > 0) db[k] = next; else delete db[k];
  });
  return db;
}

// (AVATAR_SLOTS is already declared above and reused here.)

// Merges a player's own save against the current DB copy. Mutates+returns
// `incoming`. `baseline` is the snapshot the client says it loaded; if it's
// absent (an older client), we fall back to the previous behaviour for the
// contested fields rather than guessing.
function reconcileAccountSelfWrite(incoming, current, baseline) {
  if (!current || typeof current !== "object") return incoming;

  for (const f of SERVER_OWNED_ACCOUNT_FIELDS) {
    if (Object.prototype.hasOwnProperty.call(current, f)) incoming[f] = current[f];
    else delete incoming[f];
  }

  if (!baseline || typeof baseline !== "object") return incoming;

  incoming.coins        = reconcileNumber(current.coins, incoming.coins, baseline.coins);
  incoming.ownedCarIds  = reconcileStringList(current.ownedCarIds, incoming.ownedCarIds, baseline.ownedCarIds);
  incoming.carQuantities = reconcileQtyMap(current.carQuantities, incoming.carQuantities, baseline.carQuantities);
  incoming.ownedNameTags = reconcileStringList(current.ownedNameTags, incoming.ownedNameTags, baseline.ownedNameTags);
  incoming.ownedTitles   = reconcileStringList(current.ownedTitles, incoming.ownedTitles, baseline.ownedTitles);

  incoming.ownedAvatarPieces = incoming.ownedAvatarPieces || {};
  incoming.avatarPieceQuantities = incoming.avatarPieceQuantities || {};
  for (const slot of AVATAR_SLOTS) {
    incoming.ownedAvatarPieces[slot] = reconcileStringList(
      (current.ownedAvatarPieces || {})[slot],
      (incoming.ownedAvatarPieces || {})[slot],
      (baseline.ownedAvatarPieces || {})[slot]
    );
    incoming.avatarPieceQuantities[slot] = reconcileQtyMap(
      (current.avatarPieceQuantities || {})[slot],
      (incoming.avatarPieceQuantities || {})[slot],
      (baseline.avatarPieceQuantities || {})[slot]
    );
  }

  return incoming;
}

// Resolves the acting player from the session. Admin sessions are rejected --
// these are player actions and an admin session has no player account.
async function actingPlayer(req, res) {
  const session = await getSession(req);
  if (!session || session.isAdmin) {
    res.status(401).json({ error: "authentication required" });
    return null;
  }
  const me = await loadAccount(session.username);
  if (!me) {
    res.status(404).json({ error: "account_not_found" });
    return null;
  }
  if (me.isBanned) {
    res.status(403).json({ error: "banned" });
    return null;
  }
  return me;
}

function hasFriend(acc, username) {
  return (acc.friendUsernames || []).some((u) => sameUser(u, username));
}

// Mirrors of the client-side inventory helpers. Kept behaviourally identical
// (including the legacy fallbacks and the "selling your last copy wipes its
// per-car stats" rule) so a server-side transfer produces exactly the same
// account shape the client would have.
function getCarQuantity(acc, carId) {
  if (!acc) return 0;
  if (acc.carQuantities && typeof acc.carQuantities[carId] === "number") return acc.carQuantities[carId];
  if (acc.ownedCarIds && acc.ownedCarIds.indexOf(carId) !== -1) return 1;
  return 0;
}

function addCarToInventory(acc, carId, qty) {
  qty = qty || 1;
  acc.carQuantities = acc.carQuantities || {};
  acc.carQuantities[carId] = getCarQuantity(acc, carId) + qty;
  acc.ownedCarIds = acc.ownedCarIds || [];
  if (acc.ownedCarIds.indexOf(carId) === -1) acc.ownedCarIds.push(carId);
}

function removeCarFromInventory(acc, carId, qty) {
  qty = qty || 1;
  acc.carQuantities = acc.carQuantities || {};
  const next = Math.max(0, getCarQuantity(acc, carId) - qty);
  acc.carQuantities[carId] = next;
  if (next === 0) {
    if (acc.ownedCarIds) {
      const idx = acc.ownedCarIds.indexOf(carId);
      if (idx !== -1) acc.ownedCarIds.splice(idx, 1);
    }
    if (acc.carStats && acc.carStats[carId]) delete acc.carStats[carId];
    if (acc.equippedCarId === carId) acc.equippedCarId = "starter_car";
  }
  return next;
}

function addAvatarPieceToInventory(acc, slot, pieceId) {
  acc.ownedAvatarPieces = acc.ownedAvatarPieces || { shoes: [], pants: [], shirt: [], head: [] };
  acc.ownedAvatarPieces[slot] = acc.ownedAvatarPieces[slot] || [];

  // Seed quantities from EXISTING ownership before adding the new piece.
  // Order matters: if the new pieceId is pushed into ownedAvatarPieces first,
  // this seeding pass sets it to 1 and the increment below then takes it to 2
  // -- silently handing the player a free duplicate on their first-ever piece.
  acc.avatarPieceQuantities = acc.avatarPieceQuantities || {};
  AVATAR_SLOTS.forEach((s) => {
    if (!acc.avatarPieceQuantities[s]) {
      acc.avatarPieceQuantities[s] = {};
      (acc.ownedAvatarPieces[s] || []).forEach((id) => {
        if (!acc.avatarPieceQuantities[s][id]) acc.avatarPieceQuantities[s][id] = 1;
      });
    }
  });

  if (acc.ownedAvatarPieces[slot].indexOf(pieceId) === -1) acc.ownedAvatarPieces[slot].push(pieceId);
  acc.avatarPieceQuantities[slot][pieceId] = (acc.avatarPieceQuantities[slot][pieceId] || 0) + 1;
}

function getAvatarPieceQty(acc, slot, pieceId) {
  if (acc && acc.avatarPieceQuantities && acc.avatarPieceQuantities[slot] && acc.avatarPieceQuantities[slot][pieceId] !== undefined) {
    return acc.avatarPieceQuantities[slot][pieceId];
  }
  const owned = (acc && acc.ownedAvatarPieces && acc.ownedAvatarPieces[slot]) || [];
  return owned.indexOf(pieceId) !== -1 ? 1 : 0;
}

function removeAvatarPieceFromInventory(acc, slot, pieceId, qty) {
  qty = qty || 1;
  acc.avatarPieceQuantities = acc.avatarPieceQuantities || {};
  acc.avatarPieceQuantities[slot] = acc.avatarPieceQuantities[slot] || {};
  const current = getAvatarPieceQty(acc, slot, pieceId);
  const next = Math.max(0, current - qty);
  acc.avatarPieceQuantities[slot][pieceId] = next;
  if (next <= 0) {
    acc.ownedAvatarPieces = acc.ownedAvatarPieces || {};
    acc.ownedAvatarPieces[slot] = (acc.ownedAvatarPieces[slot] || []).filter((id) => id !== pieceId);
    delete acc.avatarPieceQuantities[slot][pieceId];
    if (acc.equippedAvatar && acc.equippedAvatar[slot] === pieceId) acc.equippedAvatar[slot] = null;
  }
}

// Applies a mutual friendship to both accounts, clearing any pending
// requests in either direction.
function applyAccept(a, b) {
  a.incomingFriendRequests = (a.incomingFriendRequests || []).filter((u) => !sameUser(u, b.username));
  a.outgoingFriendRequests = (a.outgoingFriendRequests || []).filter((u) => !sameUser(u, b.username));
  a.friendUsernames = a.friendUsernames || [];
  if (!hasFriend(a, b.username)) a.friendUsernames.push(b.username);

  b.incomingFriendRequests = (b.incomingFriendRequests || []).filter((u) => !sameUser(u, a.username));
  b.outgoingFriendRequests = (b.outgoingFriendRequests || []).filter((u) => !sameUser(u, a.username));
  b.friendUsernames = b.friendUsernames || [];
  if (!hasFriend(b, a.username)) b.friendUsernames.push(a.username);
}

router.post("/friend-request", async (req, res) => {
  const me = await actingPlayer(req, res);
  if (!me) return;
  const toUsername = String((req.body && req.body.toUsername) || "").trim();
  if (!toUsername) return res.status(400).json({ error: "missing_username" });
  if (sameUser(toUsername, me.username)) return res.status(400).json({ error: "cannot_friend_self" });

  const target = await loadAccount(toUsername);
  if (!target) return res.status(404).json({ error: "recipient_not_found" });
  if (hasFriend(me, target.username)) return res.status(400).json({ error: "already_friends" });

  // If they already requested us, this is a mutual match -- accept instead of
  // creating a second, mirrored pending request.
  if ((me.incomingFriendRequests || []).some((u) => sameUser(u, target.username))) {
    applyAccept(me, target);
    await storeAccount(me);
    await storeAccount(target);
    return res.json({ ok: true, accepted: true });
  }

  if ((me.outgoingFriendRequests || []).some((u) => sameUser(u, target.username))) {
    return res.status(400).json({ error: "already_sent" });
  }

  me.outgoingFriendRequests = me.outgoingFriendRequests || [];
  me.outgoingFriendRequests.push(target.username);
  target.incomingFriendRequests = target.incomingFriendRequests || [];
  if (!target.incomingFriendRequests.some((u) => sameUser(u, me.username))) {
    target.incomingFriendRequests.push(me.username);
  }

  await storeAccount(me);
  await storeAccount(target);
  res.json({ ok: true });
});

router.post("/friend-accept", async (req, res) => {
  const me = await actingPlayer(req, res);
  if (!me) return;
  const otherUsername = String((req.body && req.body.otherUsername) || "").trim();
  if (!otherUsername) return res.status(400).json({ error: "missing_username" });

  const other = await loadAccount(otherUsername);
  if (!other) return res.status(404).json({ error: "recipient_not_found" });

  // Must actually have a pending request from them -- otherwise anyone could
  // force themselves into someone else's friends list.
  if (!(me.incomingFriendRequests || []).some((u) => sameUser(u, other.username))) {
    return res.status(400).json({ error: "no_pending_request" });
  }

  applyAccept(me, other);
  await storeAccount(me);
  await storeAccount(other);
  res.json({ ok: true });
});

// Declines an incoming request or cancels an outgoing one -- same removal on
// both sides either way.
router.post("/friend-remove-request", async (req, res) => {
  const me = await actingPlayer(req, res);
  if (!me) return;
  const otherUsername = String((req.body && req.body.otherUsername) || "").trim();
  if (!otherUsername) return res.status(400).json({ error: "missing_username" });

  me.incomingFriendRequests = (me.incomingFriendRequests || []).filter((u) => !sameUser(u, otherUsername));
  me.outgoingFriendRequests = (me.outgoingFriendRequests || []).filter((u) => !sameUser(u, otherUsername));
  await storeAccount(me);

  // Best-effort on their side -- if their account is gone, ours is still clean.
  const other = await loadAccount(otherUsername);
  if (other) {
    other.incomingFriendRequests = (other.incomingFriendRequests || []).filter((u) => !sameUser(u, me.username));
    other.outgoingFriendRequests = (other.outgoingFriendRequests || []).filter((u) => !sameUser(u, me.username));
    await storeAccount(other);
  }
  res.json({ ok: true });
});

router.post("/friend-remove", async (req, res) => {
  const me = await actingPlayer(req, res);
  if (!me) return;
  const otherUsername = String((req.body && req.body.otherUsername) || "").trim();
  if (!otherUsername) return res.status(400).json({ error: "missing_username" });

  me.friendUsernames = (me.friendUsernames || []).filter((u) => !sameUser(u, otherUsername));
  await storeAccount(me);

  const other = await loadAccount(otherUsername);
  if (other) {
    other.friendUsernames = (other.friendUsernames || []).filter((u) => !sameUser(u, me.username));
    await storeAccount(other);
  }
  res.json({ ok: true });
});

router.post("/send-coins", security.rateLimit({
  max: 30, windowMs: 5 * 60 * 1000, keyPrefix: "sendcoins",
  message: "You're sending coins too quickly. Please wait a moment.",
}), async (req, res) => {
  const me = await actingPlayer(req, res);
  if (!me) return;
  const toUsername = String((req.body && req.body.toUsername) || "").trim();
  const amount = parseInt((req.body && req.body.amount), 10);

  if (!toUsername) return res.status(400).json({ error: "missing_username" });
  if (sameUser(toUsername, me.username)) return res.status(400).json({ error: "cannot_send_self" });
  if (!Number.isFinite(amount) || amount < MIN_COINS_TO_SEND) {
    return res.status(400).json({ error: "below_minimum", min: MIN_COINS_TO_SEND });
  }
  // Balance is read from the SERVER's copy, never from anything the client
  // claims -- this is the check that actually matters.
  if ((me.coins || 0) < amount) return res.status(400).json({ error: "insufficient_coins" });

  const target = await loadAccount(toUsername);
  if (!target) return res.status(404).json({ error: "recipient_not_found" });

  me.coins = (me.coins || 0) - amount;
  target.coins = (target.coins || 0) + amount;
  target.pendingCoinNotifications = target.pendingCoinNotifications || [];
  target.pendingCoinNotifications.push({
    id: "coinnotif_" + Date.now() + "_" + Math.floor(Math.random() * 100000),
    fromUsername: me.username,
    amount: amount,
    ts: Date.now(),
  });

  // Credit the recipient first: if the debit somehow failed after this, the
  // worst case is coins created rather than a player's coins vanishing.
  await storeAccount(target);
  await storeAccount(me);
  res.json({ ok: true, coins: me.coins });
});

// Dismissing a "X sent you Y coins" notification. This needs its own route
// now that pendingCoinNotifications is server-owned: the client used to
// dismiss one by filtering its local copy and saving the whole account,
// which is exactly the stale-overwrite pattern that was losing incoming
// gifts in the first place.
router.post("/coin-notification-dismiss", async (req, res) => {
  const me = await actingPlayer(req, res);
  if (!me) return;
  const id = String((req.body && req.body.id) || "");
  if (!id) return res.status(400).json({ error: "missing_id" });

  me.pendingCoinNotifications = (me.pendingCoinNotifications || []).filter((n) => n && n.id !== id);
  await storeAccount(me);
  res.json({ ok: true, pendingCoinNotifications: me.pendingCoinNotifications });
});

router.post("/bm-buy", async (req, res) => {
  const buyer = await actingPlayer(req, res);
  if (!buyer) return;
  const listingId = String((req.body && req.body.listingId) || "");
  const listingType = String((req.body && req.body.listingType) || "");
  if (!listingId) return res.status(400).json({ error: "missing_listing" });
  if (listingType !== "car" && listingType !== "item") return res.status(400).json({ error: "bad_listing_type" });

  const key = listingType === "car" ? "black_market_listings" : "black_market_item_listings";
  let listings = [];
  try {
    const raw = await store.get("system", key, true);
    if (raw && raw.value) listings = JSON.parse(raw.value);
    if (!Array.isArray(listings)) listings = [];
  } catch (e) { listings = []; }

  const listing = listings.find((l) => l && l.id === listingId);
  if (!listing) return res.status(404).json({ error: "listing_gone" });
  if (sameUser(listing.sellerUsername, buyer.username)) return res.status(400).json({ error: "own_listing" });

  const seller = await loadAccount(listing.sellerUsername);
  if (!seller) return res.status(404).json({ error: "seller_not_found" });

  // Price comes from the stored listing, never from the request body.
  const price = parseInt(listing.price, 10);
  if (!Number.isFinite(price) || price < 0) return res.status(400).json({ error: "bad_price" });
  if ((buyer.coins || 0) < price) return res.status(400).json({ error: "insufficient_coins" });

  const remaining = listings.filter((l) => l.id !== listingId);

  if (listingType === "car") {
    // The seller must still own enough copies, accounting for any OTHER
    // listings they have up for the same car.
    const otherListings = listings.filter((l) =>
      l.id !== listingId && sameUser(l.sellerUsername, seller.username) && l.carId === listing.carId
    ).length;
    if (getCarQuantity(seller, listing.carId) <= otherListings) {
      await store.set("system", key, JSON.stringify(remaining), true); // drop the stale listing
      return res.status(409).json({ error: "listing_stale" });
    }
    addCarToInventory(buyer, listing.carId, 1);
    removeCarFromInventory(seller, listing.carId, 1);
  } else if (listing.itemType === "nameTag") {
    if (!(seller.ownedNameTags || []).some((t) => t === listing.itemImage)) {
      await store.set("system", key, JSON.stringify(remaining), true);
      return res.status(409).json({ error: "listing_stale" });
    }
    buyer.ownedNameTags = buyer.ownedNameTags || [];
    if (buyer.ownedNameTags.indexOf(listing.itemImage) === -1) buyer.ownedNameTags.push(listing.itemImage);
    seller.ownedNameTags = (seller.ownedNameTags || []).filter((t) => t !== listing.itemImage);
    if (seller.equippedNameTag === listing.itemImage) seller.equippedNameTag = null;
  } else if (listing.itemType === "avatar") {
    const otherListings = listings.filter((l) =>
      l.id !== listingId && sameUser(l.sellerUsername, seller.username) &&
      l.itemType === "avatar" && l.itemId === listing.itemId && l.slot === listing.slot
    ).length;
    if (getAvatarPieceQty(seller, listing.slot, listing.itemId) <= otherListings) {
      await store.set("system", key, JSON.stringify(remaining), true);
      return res.status(409).json({ error: "listing_stale" });
    }
    addAvatarPieceToInventory(buyer, listing.slot, listing.itemId);
    removeAvatarPieceFromInventory(seller, listing.slot, listing.itemId, 1);
  } else {
    return res.status(400).json({ error: "unknown_item_type" });
  }

  buyer.coins = (buyer.coins || 0) - price;
  seller.coins = (seller.coins || 0) + price;

  // Remove the listing BEFORE crediting, so two simultaneous buyers can't both
  // claim the same item. A dropped listing is a far better failure mode than a
  // duplicated item.
  await store.set("system", key, JSON.stringify(remaining), true);
  await storeAccount(seller);
  await storeAccount(buyer);
  res.json({ ok: true });
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
    const cascadedUsernames = await cascadeBanAccountsForIp(ip);
    res.json({ banned: true, cascadedUsernames });
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
