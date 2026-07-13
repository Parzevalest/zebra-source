// security.js — Application-level abuse protections for Panda Type.
//
// Deliberately ZERO external dependencies. An earlier attempt to add the
// `compression` npm package crash-looped the deploy (MODULE_NOT_FOUND),
// so everything here is built on Node/Express primitives only. Nothing to
// npm-install, nothing to break on deploy.
//
// IMPORTANT DESIGN NOTE ON SHARED IPs:
// Panda Type has legitimate players who share a single IP (schools, dorms,
// libraries, mobile carriers). The same reason the anti-cheat IP-cascade
// has to be careful, rate limits do too. So the limits here are tuned
// GENEROUSLY on gameplay and only strict where abuse is genuinely costly
// (login/register). A whole computer lab should still be able to play.

// ── In-memory sliding-window counters ───────────────────────────────────────
// Map<bucketKey, number[]>  where the array holds request timestamps (ms).
// In-memory means it resets on redeploy and isn't shared across instances --
// fine for this use (single Render instance, abuse windows are short).
const _hits = new Map();

// Periodic cleanup so the map can't grow unbounded from one-off IPs.
setInterval(() => {
  const now = Date.now();
  for (const [key, times] of _hits) {
    // Drop entries whose newest hit is older than 10 minutes.
    if (!times.length || now - times[times.length - 1] > 10 * 60 * 1000) {
      _hits.delete(key);
    }
  }
}, 5 * 60 * 1000).unref?.();

// Core check: is `key` under `max` hits within `windowMs`? Records the hit.
function _underLimit(key, max, windowMs) {
  const now = Date.now();
  let times = _hits.get(key);
  if (!times) { times = []; _hits.set(key, times); }
  // Drop timestamps outside the window.
  const cutoff = now - windowMs;
  while (times.length && times[0] < cutoff) times.shift();
  if (times.length >= max) return false;
  times.push(now);
  return true;
}

// Builds an Express middleware that rate-limits by client IP.
// opts: { max, windowMs, message, keyPrefix }
function rateLimit(opts) {
  const max = opts.max;
  const windowMs = opts.windowMs;
  const message = opts.message || "Too many requests. Please slow down and try again shortly.";
  const keyPrefix = opts.keyPrefix || "rl";
  return function (req, res, next) {
    // req.ip is real because server.js sets "trust proxy".
    const ip = req.ip || "unknown";
    const key = keyPrefix + ":" + ip;
    if (_underLimit(key, max, windowMs)) return next();
    res.set("Retry-After", Math.ceil(windowMs / 1000));
    return res.status(429).json({ error: "rate_limited", message });
  };
}

// ── Per-account login lockout (brute-force defense) ──────────────────────────
// Separate from IP rate limiting: this tracks failed logins per USERNAME, so
// an attacker rotating IPs still can't grind one account's password. Legit
// users who fat-finger their password a few times are unaffected (the
// threshold is generous and the window auto-expires).
const _failed = new Map(); // Map<username, { count, firstAt, lockedUntil }>

const LOCKOUT_THRESHOLD = 10;              // failed attempts before lockout
const LOCKOUT_WINDOW_MS = 15 * 60 * 1000;  // ...within this window
const LOCKOUT_DURATION_MS = 15 * 60 * 1000; // lock lasts this long

// Returns { locked: true, retryAfterSec } if this account is currently locked.
function checkAccountLock(username) {
  if (!username) return { locked: false };
  const rec = _failed.get(username.toLowerCase());
  if (!rec) return { locked: false };
  const now = Date.now();
  if (rec.lockedUntil && now < rec.lockedUntil) {
    return { locked: true, retryAfterSec: Math.ceil((rec.lockedUntil - now) / 1000) };
  }
  return { locked: false };
}

// Call on a FAILED login attempt.
function recordFailedLogin(username) {
  if (!username) return;
  const uname = username.toLowerCase();
  const now = Date.now();
  let rec = _failed.get(uname);
  if (!rec || now - rec.firstAt > LOCKOUT_WINDOW_MS) {
    rec = { count: 0, firstAt: now, lockedUntil: 0 };
    _failed.set(uname, rec);
  }
  rec.count++;
  if (rec.count >= LOCKOUT_THRESHOLD) {
    rec.lockedUntil = now + LOCKOUT_DURATION_MS;
  }
}

// Call on a SUCCESSFUL login to clear the counter.
function clearFailedLogins(username) {
  if (username) _failed.delete(username.toLowerCase());
}

// ── Security headers (helmet-equivalent, hand-rolled, no dependency) ─────────
// Conservative set -- avoids anything that could break the game's own inline
// scripts or Stripe/Cloudflare. Deliberately does NOT set a strict CSP, since
// the game uses inline scripts and a wrong CSP would break it (we saw a CSP
// 'eval' warning earlier from an extension; we don't want to add our own).
function securityHeaders(req, res, next) {
  res.set("X-Content-Type-Options", "nosniff");
  res.set("X-Frame-Options", "SAMEORIGIN");          // clickjacking protection
  res.set("Referrer-Policy", "strict-origin-when-cross-origin");
  res.set("X-XSS-Protection", "0");                   // modern browsers: disable legacy auditor
  res.set("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
  next();
}

module.exports = {
  rateLimit,
  checkAccountLock,
  recordFailedLogin,
  clearFailedLogins,
  securityHeaders,
};
