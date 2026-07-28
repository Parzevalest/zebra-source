// ── Season rank cache (server-authoritative) ────────────────────────────────
//
// Produces a username -> season rank map, computed on the SERVER from stored
// account data. This is what the top-player badges read.
//
// Why server-side: badges are shown in races and on profiles, so a
// client-computed rank could be forged ("#1 Racer" on someone who's 500th).
// Rank is decided here, from the same season points the leaderboard sorts by,
// and neither the browser nor the race client can influence it.
//
// Why cached: ranking means reading every account and sorting them. Doing that
// on every race join or profile view would hammer the database. Instead it's
// computed at most once per TTL and reused. A badge being up to a minute stale
// is fine; the leaderboard itself already updates on a similar cadence.

let db = null;
function setDb(dbModule) { db = dbModule; }

let rankCache = new Map();   // lowercased username -> rank (1-based)
let cachedAt = 0;
let building = null;         // in-flight promise, so concurrent callers share one build
const TTL_MS = 60 * 1000;

// Reads the active season id from the stored season config, so only
// current-season points are ranked. Returns null if unset, in which case all
// points count -- the correct pre-season fallback.
async function currentSeasonId() {
  if (!db) return null;
  try {
    const row = await db.get("system", "season_config", true);
    if (!row || !row.value) return null;
    const cfg = JSON.parse(row.value);
    return cfg && cfg.seasonId ? cfg.seasonId : null;
  } catch (e) {
    return null;
  }
}

// The current season id, so points from a previous season don't count. Read
// from the season config; when absent, all points count, which is the correct
// fallback before a season is configured.
async function buildRankMap(seasonIdOverride) {
  const seasonId = seasonIdOverride !== undefined ? seasonIdOverride : await currentSeasonId();
  const next = new Map();
  if (!db) { rankCache = next; cachedAt = Date.now(); return next; }

  let rows;
  try {
    rows = await db.listEntries("account:");
  } catch (e) {
    // On failure, keep whatever we had rather than wiping every badge.
    return rankCache;
  }

  const ranked = [];
  for (const row of rows) {
    let acc;
    try { acc = JSON.parse(row.value); } catch (e) { continue; }
    if (!acc || !acc.username) continue;
    // Same exclusions the leaderboard uses -- a banned or hidden account
    // doesn't hold a rank, and shouldn't push everyone below it down.
    if (acc.isBanned || acc.isSuspended || acc.excludedFromLeaderboard) continue;

    const s = acc.seasonStats || {};
    // Only count points from the CURRENT season. A stale seasonStats from a
    // previous season contributes 0, exactly as it does on the leaderboard.
    const points = (!seasonId || s.seasonId === seasonId) ? (s.points || 0) : 0;
    // Someone with no season races isn't ranked at all -- otherwise thousands
    // of 0-point accounts would fill "Top 50" on a quiet season.
    if (points <= 0) continue;

    ranked.push({ username: acc.username.toLowerCase(), points });
  }

  ranked.sort((a, b) => b.points - a.points);
  ranked.forEach((r, i) => next.set(r.username, i + 1));

  rankCache = next;
  cachedAt = Date.now();
  return next;
}

async function getRankMap() {
  if (Date.now() - cachedAt < TTL_MS && rankCache.size) return rankCache;
  if (building) return building;
  building = buildRankMap().finally(() => { building = null; });
  return building;
}

// The rank for one username, or null if unranked. Synchronous read of the
// current cache -- callers that need freshness call getRankMap first.
function rankFor(username) {
  if (!username) return null;
  return rankCache.get(username.toLowerCase()) || null;
}

// Maps a rank to its badge tier, or null if outside the top 50. This is the
// single source of truth for the tiers, shared by client and server via the
// identical copy in zebra_type.html (seasonBadgeForRank).
function badgeForRank(rank) {
  if (!rank || rank < 1) return null;
  if (rank === 1) return { label: "#1 Racer", tier: "gold" };
  if (rank === 2) return { label: "#2 Racer", tier: "silver" };
  if (rank === 3) return { label: "#3 Racer", tier: "bronze" };
  if (rank <= 10) return { label: "Top 10 Racer", tier: "blue" };
  if (rank <= 50) return { label: "Top 50 Racer", tier: "green" };
  return null;
}

module.exports = { setDb, getRankMap, rankFor, badgeForRank, buildRankMap };
