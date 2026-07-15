// db.js — A key-value store backed by MongoDB (via Mongoose).
// Replaces the old SQLite driver for compatibility with stateless hosting like Render.

const mongoose = require("mongoose");

// 1. Connect to MongoDB using the Render Environment Variable
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log("Successfully connected to MongoDB!"))
  .catch((error) => console.error("Database connection failed:", error));

// 2. Create the "Shared KV" Schema
const sharedSchema = new mongoose.Schema({
  key: { type: String, required: true, unique: true },
  value: { type: String, required: true },
  updated_at: { type: Number, default: Date.now }
});
const SharedKV = mongoose.model("SharedKV", sharedSchema);

// 3. Create the "Private KV" Schema
const privateSchema = new mongoose.Schema({
  owner: { type: String, required: true },
  key: { type: String, required: true },
  value: { type: String, required: true },
  updated_at: { type: Number, default: Date.now }
});
// Ensures a user can only have one specific key (like one active car)
privateSchema.index({ owner: 1, key: 1 }, { unique: true });
const PrivateKV = mongoose.model("PrivateKV", privateSchema);

// --- DATABASE FUNCTIONS ---

async function get(owner, key, shared) {
  let row;
  if (shared) {
    row = await SharedKV.findOne({ key: key });
  } else {
    row = await PrivateKV.findOne({ owner: owner, key: key });
  }
  
  if (!row) return null;
  return { key, value: row.value, shared: !!shared };
}

async function set(owner, key, value, shared) {
  const now = Date.now();
  
  if (shared) {
    // findOneAndUpdate with upsert: true acts like the old "ON CONFLICT DO UPDATE"
    await SharedKV.findOneAndUpdate(
      { key: key },
      { value: value, updated_at: now },
      { upsert: true, new: true }
    );
  } else {
    await PrivateKV.findOneAndUpdate(
      { owner: owner, key: key },
      { value: value, updated_at: now },
      { upsert: true, new: true }
    );
  }
  
  return { key, value, shared: !!shared };
}

async function del(owner, key, shared) {
  let existingRow;
  
  if (shared) {
    existingRow = await SharedKV.findOneAndDelete({ key: key });
  } else {
    existingRow = await PrivateKV.findOneAndDelete({ owner: owner, key: key });
  }
  
  const existed = !!existingRow;
  return { key, deleted: existed, shared: !!shared };
}

async function list(owner, prefix, shared) {
  // Use regex to match keys that start with the prefix (like the old SQL 'LIKE ?%')
  const regexPattern = new RegExp('^' + (prefix || ''));
  let rows;

  if (shared) {
    rows = await SharedKV.find({ key: { $regex: regexPattern } });
  } else {
    rows = await PrivateKV.find({ owner: owner, key: { $regex: regexPattern } });
  }

  return { keys: rows.map((r) => r.key), prefix: prefix || "", shared: !!shared };
}

// Deletes stale session_ and challenge_ records from SharedKV. These are
// meant to be temporary (sessions ~7 days, login challenges ~2 minutes),
// but nothing was ever proactively deleting them -- a record was only
// ever removed if someone happened to try using that *exact* expired
// token/challenge again later, which almost never naturally happens.
// Every visit to the login page, finished or not, was leaving a
// permanent, unused document behind -- this is what actually cleans
// those up. A MongoDB TTL index isn't used here on purpose: SharedKV
// also holds permanent game data (accounts, guilds, wheel configs, etc.)
// in the same collection, and a TTL index applies to the whole
// collection with no way to exempt those by key prefix -- it would
// eventually delete real game data too. Explicit, prefix-scoped deletes
// like this are the safe way to do it given that shared layout.
async function cleanupExpiredAuthKeys() {
  const now = Date.now();
  const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000; // must match storageRoutes.js
  const CHALLENGE_TTL_MS = 2 * 60 * 1000;          // must match storageRoutes.js

  const sessionResult = await SharedKV.deleteMany({
    key: { $regex: /^session_/ },
    updated_at: { $lt: now - SESSION_TTL_MS }
  });
  const challengeResult = await SharedKV.deleteMany({
    key: { $regex: /^challenge_/ },
    updated_at: { $lt: now - CHALLENGE_TTL_MS }
  });

  return {
    sessionsDeleted: sessionResult.deletedCount || 0,
    challengesDeleted: challengeResult.deletedCount || 0
  };
}

// Finds every account document whose stored lastKnownIp matches the given
// IP. Accounts are stored as one big JSON string per document (no separate
// lastKnownIp column to query directly), so this does a regex substring
// match against the raw stored value -- one query instead of fetching
// every single account individually just to check one field. The IP is
// regex-escaped and anchored with the closing quote so e.g. banning
// "1.2.3.4" can never accidentally match "1.2.3.44".
async function findAccountsByLastKnownIp(ip) {
  if (!ip) return [];
  const escaped = ip.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const pattern = new RegExp('"lastKnownIp":"' + escaped + '"');
  const rows = await SharedKV.find({ key: { $regex: /^account:/ }, value: { $regex: pattern } });
  return rows.map((r) => ({ key: r.key, value: r.value }));
}

// Returns full records -- key AND value -- for every SharedKV key starting
// with `prefix`, in a single query.
//
// list() above deliberately returns keys only, which is all its callers need.
// The admin ban screens need the stored JSON as well (who, when, why), and
// calling get() once per key after a list() would be one database round trip
// per ban. This is the same one-query shape as findAccountsByLastKnownIp.
//
// The prefix is regex-escaped before it goes anywhere near a RegExp. Note
// that list() does NOT do this -- it interpolates the caller's prefix
// straight in -- so a prefix containing regex metacharacters silently matches
// the wrong keys there. Both current callers pass fixed literals ("ipban_",
// "ban_"), but escaping costs nothing and closes the trap for future ones.
async function listEntries(prefix) {
  const escaped = String(prefix || "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const rows = await SharedKV.find({ key: { $regex: new RegExp("^" + escaped) } });
  return rows.map((r) => ({ key: r.key, value: r.value, updated_at: r.updated_at }));
}

// Export the functions for the router to use
module.exports = { get, set, del, list, listEntries, cleanupExpiredAuthKeys, findAccountsByLastKnownIp };
