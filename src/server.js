require("dotenv").config();
const express = require("express");
const cors = require("cors");
const http = require("http");
const path = require("path");

const storageRoutes = require("./storageRoutes");
const stripeRoutes = require("./stripeRoutes");
const { handleStripeWebhook } = require("./stripeWebhook");
const { makeRaceServer, setDb } = require("./race");
const db = require("./db");
const security = require("./security");

const app = express();
// Render sits behind a reverse proxy -- without this, req.ip would always
// return the proxy's internal address instead of the visitor's real IP,
// which would make IP-based banning completely non-functional.
app.set("trust proxy", true);

// Conservative security headers on every response (clickjacking, MIME
// sniffing, referrer policy). No strict CSP -- the game relies on inline
// scripts and a wrong CSP would break it.
app.use(security.securityHeaders);

app.use(cors({
  origin: ["https://pandatype.org", "https://www.pandatype.org", "http://localhost:3000"],
  credentials: true
}));

// Stripe webhook: MUST be registered before express.json() below.
// Stripe signs the raw, exact bytes of the request body -- once
// express.json() has parsed and re-serialized it, signature verification
// would fail every time. express.raw() here keeps this one route's body
// untouched while every other route still gets normal JSON parsing.
app.post("/api/stripe-webhook", express.raw({ type: "application/json" }), handleStripeWebhook);

app.use(express.json({ limit: "10mb" }));

// Broad API rate limit -- a ceiling against a single IP flooding the API,
// tuned GENEROUSLY so normal gameplay (and shared school/dorm IPs with many
// legit players) never hits it. This is a backstop, not a fine-grained
// control; the strict limits live on login/register inside storageRoutes.
// 600 requests / minute / IP ~= 10 req/sec sustained, far above what a real
// player generates but well below what a flood would.
app.use("/api", security.rateLimit({
  max: 600,
  windowMs: 60 * 1000,
  keyPrefix: "api",
  message: "You're sending requests too quickly. Please slow down for a moment.",
}));

app.use("/api", storageRoutes);
app.use("/api", stripeRoutes);

app.get("/health", (req, res) => {
  res.json({ ok: true, time: Date.now() });
});

// Serve static files from public/
app.use(express.static(path.join(__dirname, "..", "public")));

// Catch-all: serve the SPA for all non-API routes
app.use((req, res) => {
  res.sendFile(path.join(__dirname, "..", "public", "zebra_type.html"));
});

const httpServer = http.createServer(app);
setDb(db);
makeRaceServer(httpServer);

const PORT = process.env.PORT || 3001;
httpServer.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
  console.log(`  Game:       http://localhost:${PORT}`);
  console.log(`  HTTP API:   http://localhost:${PORT}/api`);
  console.log(`  WebSocket:  ws://localhost:${PORT}/race`);
});

// Clean up expired session/login-challenge records once at boot, then
// every hour going forward -- see db.js for why this can't just be a
// MongoDB TTL index (SharedKV holds permanent game data too).
async function runAuthCleanup() {
  try {
    const result = await db.cleanupExpiredAuthKeys();
    if (result.sessionsDeleted || result.challengesDeleted) {
      console.log(`[cleanup] removed ${result.sessionsDeleted} expired session(s), ${result.challengesDeleted} expired login challenge(s)`);
    }
  } catch (e) {
    console.error("[cleanup] auth key cleanup failed:", e.message);
  }
}
runAuthCleanup();
setInterval(runAuthCleanup, 60 * 60 * 1000);
