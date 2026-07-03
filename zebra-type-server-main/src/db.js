// db.js — a key-value store backed by SQLite, shaped to match the game's
// existing window.storage interface exactly: get/set/list/delete, each
// taking a key and a "shared" flag. Two physical tables (private vs
// shared) keep the semantics identical to the original Claude.ai storage:
// "shared" data is visible to everyone, "private" data isn't (the server
// enforces that per-user — see storageRoutes.js for how a request's
// owner is determined).
//
// Tries better-sqlite3 first (the standard, fastest driver — needs a C++
// build toolchain at install time, which any normal server has) and
// automatically falls back to node-sqlite3-wasm (pure JS, no compiler
// needed, slightly slower) if that's unavailable. This means `npm
// install && npm start` works out of the box even on a machine without
// build tools set up — useful for quick local testing — while production
// deployments still get the faster native driver as long as
// better-sqlite3 installed successfully.
const path = require("path");

const dbPath = process.env.DB_PATH || path.join(__dirname, "..", "data.sqlite");

let driver; // "native" | "wasm"
let db, sharedGet, sharedSet, sharedDel, sharedList, privateGet, privateSet, privateDel, privateList;

try {
  const Database = require("better-sqlite3");
  db = new Database(dbPath);
  db.pragma("journal_mode = WAL");
  driver = "native";

  db.exec(`
    CREATE TABLE IF NOT EXISTS shared_kv (
      key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS private_kv (
      owner TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL, updated_at INTEGER NOT NULL,
      PRIMARY KEY (owner, key)
    );
  `);

  sharedGet = db.prepare("SELECT value FROM shared_kv WHERE key = ?");
  sharedSet = db.prepare(
    "INSERT INTO shared_kv (key, value, updated_at) VALUES (?, ?, ?) " +
    "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at"
  );
  sharedDel = db.prepare("DELETE FROM shared_kv WHERE key = ?");
  sharedList = db.prepare("SELECT key FROM shared_kv WHERE key LIKE ?");

  privateGet = db.prepare("SELECT value FROM private_kv WHERE owner = ? AND key = ?");
  privateSet = db.prepare(
    "INSERT INTO private_kv (owner, key, value, updated_at) VALUES (?, ?, ?, ?) " +
    "ON CONFLICT(owner, key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at"
  );
  privateDel = db.prepare("DELETE FROM private_kv WHERE owner = ? AND key = ?");
  privateList = db.prepare("SELECT key FROM private_kv WHERE owner = ? AND key LIKE ?");
} catch (e) {
  console.warn("[db] better-sqlite3 unavailable (" + e.message + ") — falling back to the pure-JS WASM driver. This is fine for local dev; for production, run `npm install` somewhere with a C++ build toolchain so the faster native driver installs instead.");
  const { Database } = require("node-sqlite3-wasm");
  db = new Database(dbPath);
  driver = "wasm";

  db.run(`CREATE TABLE IF NOT EXISTS shared_kv (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at INTEGER NOT NULL)`);
  db.run(`CREATE TABLE IF NOT EXISTS private_kv (owner TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY (owner, key))`);
}

function get(owner, key, shared) {
  let row;
  if (driver === "native") {
    row = shared ? sharedGet.get(key) : privateGet.get(owner, key);
  } else {
    row = shared
      ? db.get("SELECT value FROM shared_kv WHERE key = ?", [key])
      : db.get("SELECT value FROM private_kv WHERE owner = ? AND key = ?", [owner, key]);
  }
  if (!row) return null;
  return { key, value: row.value, shared: !!shared };
}

function set(owner, key, value, shared) {
  const now = Date.now();
  if (driver === "native") {
    if (shared) sharedSet.run(key, value, now);
    else privateSet.run(owner, key, value, now);
  } else {
    if (shared) {
      db.run(
        "INSERT INTO shared_kv (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
        [key, value, now]
      );
    } else {
      db.run(
        "INSERT INTO private_kv (owner, key, value, updated_at) VALUES (?, ?, ?, ?) ON CONFLICT(owner, key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
        [owner, key, value, now]
      );
    }
  }
  return { key, value, shared: !!shared };
}

function del(owner, key, shared) {
  const existing = get(owner, key, shared);
  const existed = !!existing;
  if (driver === "native") {
    if (shared) sharedDel.run(key);
    else privateDel.run(owner, key);
  } else {
    if (shared) db.run("DELETE FROM shared_kv WHERE key = ?", [key]);
    else db.run("DELETE FROM private_kv WHERE owner = ? AND key = ?", [owner, key]);
  }
  return { key, deleted: existed, shared: !!shared };
}

function list(owner, prefix, shared) {
  const likePattern = (prefix || "") + "%";
  let rows;
  if (driver === "native") {
    rows = shared ? sharedList.all(likePattern) : privateList.all(owner, likePattern);
  } else {
    rows = shared
      ? db.all("SELECT key FROM shared_kv WHERE key LIKE ?", [likePattern])
      : db.all("SELECT key FROM private_kv WHERE owner = ? AND key LIKE ?", [owner, likePattern]);
  }
  return { keys: rows.map((r) => r.key), prefix: prefix || "", shared: !!shared };
}

module.exports = { get, set, del, list, db, driver };

