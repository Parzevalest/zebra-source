// race.js — multiplayer race server with per-player adaptive passages.
// Each player gets a passage length tuned to their recent WPM so that
// everyone races for ~TARGET_RACE_SECONDS regardless of typing speed.
// All players start from the same sentence-boundary position in the
// shared text pool, but each receives only as many characters as they
// personally need.

const WebSocket = require("ws");
const crypto = require("crypto");

const ROOM_SIZE = 4;
const JOIN_WINDOW_MS = 3000;
const COUNTDOWN_MS = 5000;
const TARGET_RACE_SECONDS = 20; // target race duration in seconds
const CHARS_PER_WORD = 5;       // standard WPM measurement unit
const DEFAULT_WPM = 60;         // fallback if a player has no history
const MIN_CHARS = 80;           // never give a passage shorter than this
const MAX_CHARS = 1200;         // never give a passage longer than this

// Fallback passages used when no admin-uploaded texts exist.
const FALLBACK_PASSAGES = [
  "The engine roared to life as the racer gripped the wheel and watched the lights turn green. Practice makes perfect when you commit to showing up every single day no matter how you feel.",
  "Typing quickly is a skill built through repetition, focus, and a calm steady hand on the keys. The quick brown fox jumps over the lazy dog while the rain falls softly on the empty street.",
  "Every great driver started somewhere, learning the track one corner at a time until the lines became instinct. Speed comes from confidence, and confidence comes from knowing exactly what to do.",
];

// In-memory cache of admin-uploaded passage texts.
// Refreshed from storage whenever a room locks.
let passageTexts = []; // array of strings (large bodies of text)
let passageTextsLastLoaded = 0; // timestamp of last successful load
const PASSAGE_CACHE_MS = 60 * 1000; // reload from DB at most once per minute

// db module — loaded lazily so this file can still be required without it
// (tests, etc.), but in practice server.js always sets it before any room locks.
let db = null;
function setDb(dbModule) { db = dbModule; }

// ── Filler race bots ────────────────────────────────────────────────────────
// A small roster of server-simulated "players" that can fill an otherwise
// solo race so nobody races completely alone. These are NOT designed to
// impersonate a specific real person or to pass off fabricated results as a
// real human's performance -- they're plainly filler opponents, excluded
// from every leaderboard, with fixed/frozen profile stats that never change.
// Their races never touch a real account, never call back into any
// client-side stat-saving code, and never affect any real player's data.
const RACE_BOTS = [
  { username: "bot1", displayName: "Martha", carId: "car_1783141883041_9526", titleText: "Panda Type Bot", titleRarity: "Common" },
  { username: "bot2",  displayName: "Chud",  carId: "car_1783141805661_1655", titleText: "Panda Type Bot", titleRarity: "Common" },
  { username: "bot3",displayName: "Luh Krank",carId: "car_1783563053047_1965", titleText: "Panda Type Bot", titleRarity: "Common" },
  { username: "bot4",  displayName: "Zhara",  carId: "car_1783151943195_8262", titleText: "Panda Type Bot", titleRarity: "Common" },
  { username: "bot5", displayName: "Meg", carId: "car_1783241897969_850", titleText: "Panda Type Bot", titleRarity: "Common" },
];
const BOT_MIN_WPM = 60;
const BOT_MAX_WPM = 130;
const BOT_PROGRESS_TICKS = 5; // how many opponent_progress updates a bot sends over the course of a race

// Creates each bot's account in storage if it doesn't already exist yet.
// Never overwrites an existing one (so nothing here can clobber any manual
// admin tweaks made to a bot account later). Fire-and-forget at startup --
// the race server itself doesn't need to wait on this to start listening.
async function ensureBotAccountsExist() {
  if (!db) return;
  for (const bot of RACE_BOTS) {
    try {
      const key = "account:" + bot.username;
      const existing = await db.get("system", key, true);
      if (existing && existing.value) continue;
      const account = {
        username: bot.username,
        displayName: bot.displayName,
        // Random, never-revealed password -- these accounts are never meant
        // to be logged into through the normal auth flow at all.
        passwordHash: crypto.randomBytes(32).toString("hex"),
        races: 100,
        sumWpm: 100 * 100,      // averages out to exactly 100 avg WPM
        sumAccuracy: 95 * 100,  // averages out to exactly 95% avg accuracy
        bestWpm: 100,
        coins: 0,
        equippedCarId: bot.carId,
        ownedCarIds: [],
        ownedTitles: [],
        equippedTitle: null,
        excludedFromLeaderboard: true,
        isBot: true,
        createdAt: Date.now(),
      };
      await db.set("system", key, JSON.stringify(account), true);
      console.log(`[race bots] created bot account: ${bot.username}`);
    } catch (e) {
      console.warn(`[race bots] failed to ensure bot account ${bot.username}:`, e.message);
    }
  }
}

// Load passage texts from shared storage key "race_passages".
// Uses a short cache so rapid room creation doesn't hammer the DB,
// but always reloads if the cache is stale so admin changes take effect.
async function loadPassageTexts() {
  if (!db) return;
  const now = Date.now();
  if (passageTexts.length > 0 && now - passageTextsLastLoaded < PASSAGE_CACHE_MS) return;
  try {
    const row = await db.get("system", "race_passages", true);
    if (row && row.value) {
      const parsed = JSON.parse(row.value);
      if (Array.isArray(parsed) && parsed.length > 0) {
        passageTexts = parsed.filter(t => typeof t === "string" && t.trim().length > 50)
                             .map(normalizePassage);
        passageTextsLastLoaded = now;
        console.log(`[race] Loaded ${passageTexts.length} passage text(s) from DB.`);
      } else {
        console.log("[race] race_passages key exists but contains no valid texts — using fallbacks.");
      }
    } else {
      console.log("[race] race_passages key not found in DB — using fallbacks.");
    }
  } catch (e) {
    console.warn("[race] Could not load passage texts:", e.message);
  }
}

// Normalize a passage string — replace smart/curly quotes and apostrophes
// with their plain ASCII equivalents so typed characters always match.
function normalizePassage(text) {
  return text
    .replace(/[\u2018\u2019\u02BC\u0060\u00B4]/g, "'") // curly apostrophes → straight
    .replace(/[\u201C\u201D]/g, '"')                    // curly double quotes → straight
    .replace(/[\u2013\u2014]/g, '-')                    // en/em dash → hyphen
    .replace(/\u2026/g, '...');                         // ellipsis → three dots
}

// Returns the active text pool — admin texts if any, otherwise fallbacks.
function getTextPool() {
  const pool = passageTexts.length > 0 ? passageTexts : FALLBACK_PASSAGES;
  return pool.map(normalizePassage);
}

// Find all sentence-start positions in a text.
// A sentence starts after ". ", "! ", or "? " (or at position 0).
function sentenceStartPositions(text) {
  const positions = [0];
  for (let i = 0; i < text.length - 1; i++) {
    if ((text[i] === "." || text[i] === "!" || text[i] === "?") && text[i + 1] === " ") {
      const next = i + 2;
      if (next < text.length) positions.push(next);
    }
  }
  return positions;
}

// Calculate how many characters a player needs to type for ~TARGET_RACE_SECONDS.
function targetCharCount(wpm) {
  const w = Math.max(20, wpm || DEFAULT_WPM);
  const chars = Math.round((w * CHARS_PER_WORD * TARGET_RACE_SECONDS) / 60);
  return Math.max(MIN_CHARS, Math.min(MAX_CHARS, chars));
}

// Pick a passage for a specific player.
// All players in a room share the same startPos (chosen once when the room
// locks), but each gets their own character count based on their WPM.
function pickPassageForPlayer(text, startPos, wpm) {
  const needed = targetCharCount(wpm);
  const raw = text.slice(startPos, startPos + needed);
  // If we'd run off the end of the text, wrap around from the beginning.
  const segment = (raw.length < MIN_CHARS
    ? text.slice(0, Math.max(MIN_CHARS, needed))
    : raw).trimEnd();
  // Never end mid-word — cut back to the last space before the end.
  const lastSpace = segment.lastIndexOf(' ');
  const cutAt = lastSpace > MIN_CHARS / 2 ? lastSpace : segment.length;
  return segment.slice(0, cutAt).trim();
}

// Choose a shared start position for a room — same for all players.
// minChars ensures there's enough text left for the longest passage needed.
function pickStartPos(text, minChars) {
  const needed = minChars || MIN_CHARS;
  const positions = sentenceStartPositions(text);
  // Only pick positions that leave enough text for the longest passage.
  const viable = positions.filter(p => text.length - p >= needed);
  if (viable.length === 0) {
    // If no sentence start has enough room, start from beginning
    return 0;
  }
  return viable[Math.floor(Math.random() * viable.length)];
}

function makeRaceServer(httpServer) {
  const wss = new WebSocket.Server({ server: httpServer, path: "/race" });

  const rooms = new Map();
  let openRoom = null;

  // Track which usernames are currently in an active race.
  // Prevents the same player from joining two rooms simultaneously.
  const activePlayers = new Map(); // username -> ws

  // Track which bots are currently occupying a room, so the same bot can
  // never appear in two rooms at once.
  const activeBotUsernames = new Set();

  ensureBotAccountsExist().catch(() => {});

  function send(ws, msg) {
    if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(msg));
  }

  function broadcastToRoom(room, msg, exceptUsername) {
    room.players.forEach((p, username) => {
      if (username === exceptUsername) return;
      send(p.ws, msg);
    });
  }

  function opponentList(room, exceptUsername) {
    const list = [];
    room.players.forEach((p, username) => {
      if (username === exceptUsername) return;
      // nameTag was missing here, which is the whole reason opponents showed a
      // default tag: the client renders whatever this list gives it, and it
      // was never given one.
      list.push({ username, carId: p.carId, displayName: p.displayName || "", guildTag: p.guildTag || "", guildColor: p.guildColor || "", titleText: p.titleText || "", titleRarity: p.titleRarity || "", nameTag: p.nameTag || "" });
    });
    return list;
  }

  function roomHasRealPlayer(room) {
    for (const [, p] of room.players) { if (!p.isBot) return true; }
    return false;
  }

  // If a room is about to lock with only one participant, fill it with one
  // available bot so that player doesn't race completely alone. If a second
  // real player joins in time on their own, this never fires at all.
  async function injectBotIfNeeded(room) {
    if (!rooms.has(room.id) || room.locked) return;
    if (room.players.size !== 1) return;
    const available = RACE_BOTS.filter(b => !activeBotUsernames.has(b.username));
    if (!available.length) return; // all bots already busy elsewhere -- just skip
    const bot = available[Math.floor(Math.random() * available.length)];
    activeBotUsernames.add(bot.username);

    // Pull the bot's CURRENT account data (display name, equipped car) so an
    // admin editing these through the normal admin panel actually takes
    // effect -- the RACE_BOTS entries above are only used as a fallback if
    // this lookup fails for any reason, never as the source of truth.
    let liveAccount = null;
    if (db) {
      try {
        const res = await db.get("system", "account:" + bot.username, true);
        if (res && res.value) liveAccount = JSON.parse(res.value);
      } catch (e) {}
    }
    // The room may have changed while that lookup was in flight (a second
    // real player could have joined) -- bail out if it's no longer solo.
    if (!rooms.has(room.id) || room.locked || room.players.size !== 1) {
      activeBotUsernames.delete(bot.username);
      return;
    }

    const fakeWs = { readyState: WebSocket.OPEN, send: () => {}, roomId: room.id };
    const recentWpm = BOT_MIN_WPM + Math.floor(Math.random() * (BOT_MAX_WPM - BOT_MIN_WPM + 1));
    room.players.set(bot.username, {
      ws: fakeWs,
      carId: (liveAccount && liveAccount.equippedCarId) || bot.carId,
      recentWpm,
      displayName: (liveAccount && liveAccount.displayName) || bot.displayName,
      guildTag: "", guildColor: "",
      titleText: bot.titleText || "",
      titleRarity: bot.titleRarity || "",
      isBot: true,
    });
    broadcastToRoom(room, { type: "room_joined", roomId: room.id, opponentsSoFar: opponentList(room, null) }, null);
  }

  // Simulates a bot's whole race after the countdown ends: a handful of
  // progress updates broadcast to the real player(s) in the room over the
  // course of the race, then a finish at a duration consistent with the
  // bot's assigned WPM for this race. None of this touches the bot's own
  // account -- its profile stats stay exactly as seeded, always.
  function scheduleBotRace(room, username, playerData, passage) {
    const wpm = playerData.recentWpm;
    const totalChars = passage.length;
    const durationMs = Math.max(4000, Math.round(((totalChars / CHARS_PER_WORD) / wpm) * 60000));
    const accuracy = Math.round((92 + Math.random() * 6) * 10) / 10; // ~92-98%, cosmetic only

    const untilStart = Math.max(0, room.startsAt - Date.now());

    for (let i = 1; i <= BOT_PROGRESS_TICKS; i++) {
      const tickDelay = untilStart + Math.round((durationMs * i) / (BOT_PROGRESS_TICKS + 1));
      setTimeout(() => {
        if (!rooms.has(room.id) || room.finishedOrder.some(f => f.username === username)) return;
        const charsTyped = Math.round((totalChars * i) / (BOT_PROGRESS_TICKS + 1));
        const jitteredWpm = Math.max(1, Math.round(wpm + (Math.random() * 10 - 5)));
        broadcastToRoom(room, { type: "opponent_progress", username, charsTyped, wpm: jitteredWpm }, username);
      }, tickDelay);
    }

    setTimeout(() => {
      if (!rooms.has(room.id)) return;
      finishPlayerRace(room, username, Math.round(wpm), accuracy, durationMs, true);
    }, untilStart + durationMs);
  }

  async function lockAndStartCountdown(room) {
    room.locked = true;
    if (openRoom === room) openRoom = null;

    // Refresh passage texts from storage each time a room locks
    // so admin changes take effect without a server restart.
    await loadPassageTexts();
    const pool = getTextPool();
    const text = pool[Math.floor(Math.random() * pool.length)];
    // Calculate the most chars any player in this room could need,
    // so the start position always leaves enough text for everyone.
    let maxCharsNeeded = MIN_CHARS;
    room.players.forEach((p) => {
      maxCharsNeeded = Math.max(maxCharsNeeded, targetCharCount(p.recentWpm));
    });
    const startPos = pickStartPos(text, maxCharsNeeded);

    room.startsAt = Date.now() + COUNTDOWN_MS;

    // Send each player their own personal passage based on their WPM.
    room.players.forEach((p, username) => {
      const passage = pickPassageForPlayer(text, startPos, p.recentWpm);
      p.passage = passage; // stored for server-side WPM validation on finish
      send(p.ws, {
        type: "race_starting",
        roomId: room.id,
        opponents: opponentList(room, username),
        passage: passage,
        startsAt: room.startsAt,
      });
      if (p.isBot) scheduleBotRace(room, username, p, passage);
    });
  }

  // A player's equipped name tag is a data URL (an image inlined as text), not
  // an id -- see equippedNameTag in zebra_type.html. That means it travels on
  // the wire in full, and gets re-sent to every player each time someone joins.
  // A cap keeps one oversized tag from turning a 4-player room into megabytes
  // of traffic on every join. Over the limit, the player just shows a default
  // tag to others rather than the room paying for it.
  const NAME_TAG_MAX_CHARS = 96 * 1024;

  function safeNameTag(tag) {
    if (typeof tag !== "string" || !tag) return "";
    if (tag.length > NAME_TAG_MAX_CHARS) return "";
    return tag;
  }

  function joinRoom(ws, username, carId, recentWpm, displayName, guildTag, guildColor, titleText, titleRarity, nameTag) {
    let room = openRoom;
    if (!room || room.locked || room.players.size >= ROOM_SIZE) {
      const roomId = crypto.randomBytes(6).toString("hex");
      room = { id: roomId, players: new Map(), locked: false, joinTimer: null, botCheckTimer: null, finishedOrder: [] };
      rooms.set(roomId, room);
      openRoom = room;
      room.joinTimer = setTimeout(() => lockAndStartCountdown(room), JOIN_WINDOW_MS);
      // Give real players a couple seconds to join naturally first -- if a
      // second real player joins in time, injectBotIfNeeded is a no-op.
      room.botCheckTimer = setTimeout(() => injectBotIfNeeded(room), Math.max(500, JOIN_WINDOW_MS - 1000));
    }

    room.players.set(username, { ws, carId, recentWpm: recentWpm || DEFAULT_WPM, displayName: displayName || "", guildTag: guildTag || "", guildColor: guildColor || "", titleText: titleText || "", titleRarity: titleRarity || "", nameTag: safeNameTag(nameTag) });
    ws.roomId = room.id;
    ws.username = username;

    send(ws, { type: "room_joined", roomId: room.id, opponentsSoFar: opponentList(room, username) });
    broadcastToRoom(room, { type: "room_joined", roomId: room.id, opponentsSoFar: opponentList(room, ws.username) }, username);

    if (room.players.size >= ROOM_SIZE && !room.locked) {
      clearTimeout(room.joinTimer);
      if (room.botCheckTimer) clearTimeout(room.botCheckTimer);
      // Small delay so all players receive room_joined before race_starting,
      // ensuring the full countdown plays on every client.
      room.joinTimer = setTimeout(() => lockAndStartCountdown(room), 1000);
    }
  }

  // Records a soft timing-suspicion flag for admin review (NOT a ban).
  // Appends to a capped, rolling list under a single storage key. Failures
  // are swallowed by the caller -- a flag never blocks or delays a race.
  const TIMING_FLAGS_KEY = "anticheat_timing_flags";
  async function recordTimingFlag(username, wpm, accuracy, timing) {
    if (!db) return;
    try {
      let list = [];
      try {
        const row = await db.get("system", TIMING_FLAGS_KEY, true);
        if (row && row.value) list = JSON.parse(row.value);
        if (!Array.isArray(list)) list = [];
      } catch (e) { list = []; }

      list.push({
        username,
        wpm,
        accuracy,
        cv: timing.cv,
        clusterRatio: timing.clusterRatio,
        reason: timing.roboticallyUniform ? "uniform_cadence" : "tight_cluster",
        at: Date.now(),
      });

      // Keep only the most recent 200 flags so this never grows unbounded.
      if (list.length > 200) list = list.slice(list.length - 200);

      await db.set("system", TIMING_FLAGS_KEY, JSON.stringify(list), true);
      console.log(`[race] timing flag recorded for ${username} (cv=${timing.cv}, cluster=${timing.clusterRatio})`);
    } catch (e) {
      // Non-fatal -- never let flag storage interfere with the race.
    }
  }

  // Analyzes the server-observed spacing between a player's progress
  // updates. Returns a suspicion result. This runs entirely on data the
  // server collected itself (arrival timestamps), so it cannot be spoofed
  // by a manipulated client the way a self-reported WPM/accuracy can.
  //
  // The core idea: real human typing is bursty -- fast runs, natural
  // pauses, variable rhythm. An autotyper that types at a fixed WPM (like
  // the extension autotyper) produces progress updates at a near-constant
  // interval. We measure how much the char-per-second rate varies between
  // consecutive samples; too little variation across a long-enough race is
  // a strong tell.
  function analyzeProgressTiming(samples) {
    if (!samples || samples.length < 8) return { insufficient: true };

    // Build per-interval typing rates (chars per second) between updates.
    const rates = [];
    for (let i = 1; i < samples.length; i++) {
      const dtMs = samples[i].at - samples[i - 1].at;
      const dChars = samples[i].chars - samples[i - 1].chars;
      // Ignore zero/negative intervals and non-advancing samples.
      if (dtMs > 0 && dChars > 0) {
        rates.push((dChars / dtMs) * 1000);
      }
    }
    if (rates.length < 6) return { insufficient: true };

    const mean = rates.reduce((a, b) => a + b, 0) / rates.length;
    if (mean <= 0) return { insufficient: true };
    const variance = rates.reduce((a, b) => a + (b - mean) ** 2, 0) / rates.length;
    const std = Math.sqrt(variance);
    const cv = std / mean; // coefficient of variation -- lower = more robotic

    // Also measure how many intervals fall very close to the mean rate --
    // an autotyper clusters tightly around its target rate.
    const nearMean = rates.filter((r) => Math.abs(r - mean) / mean < 0.12).length;
    const clusterRatio = nearMean / rates.length;

    // Thresholds chosen conservatively so ordinary humans (who vary a lot)
    // don't trip them. A real typist's CV is typically well above 0.35;
    // metronomic automation sits far below that.
    const roboticallyUniform = cv < 0.18 && rates.length >= 10;
    const tightlyClustered = clusterRatio > 0.85 && rates.length >= 10;

    return {
      insufficient: false,
      sampleCount: rates.length,
      cv: +cv.toFixed(3),
      clusterRatio: +clusterRatio.toFixed(2),
      roboticallyUniform,
      tightlyClustered,
      suspicious: roboticallyUniform || tightlyClustered,
    };
  }

  // Shared by both a real "finished" message and a bot's simulated finish.
  // skipWpmCheck is used for bots, since their wpm/timeMs pair is already
  // internally consistent (the server generated both itself) -- the
  // sanity check exists to catch manipulated results from a real client.
  function finishPlayerRace(room, username, wpm, accuracy, timeMs, skipWpmCheck) {
    if (!room || !room.locked) return;
    if (room.finishedOrder.some((f) => f.username === username)) return;

    if (!skipWpmCheck) {
      const playerData = room.players.get(username);
      if (playerData && room.startsAt && timeMs > 0) {
        const passageLen = playerData.passage ? playerData.passage.length : 0;
        if (passageLen > 0) {
          const elapsedMinutes = timeMs / 60000;
          const impliedWpm = Math.round((passageLen / 5) / elapsedMinutes);
          const SERVER_WPM_CAP = 350;
          if (impliedWpm > SERVER_WPM_CAP) {
            wpm = SERVER_WPM_CAP;
            console.warn(`[race] WPM clamped for ${username}: implied ${impliedWpm} → ${SERVER_WPM_CAP}`);
          }
        }

        // Server-side timing analysis on the progress updates we timestamped
        // ourselves. This is a SOFT signal -- an unusually steady human could
        // in principle trip it -- so it records a review flag rather than
        // auto-banning. Admins see flagged players in the panel and decide.
        const timing = analyzeProgressTiming(playerData.progressSamples);
        if (timing && timing.suspicious) {
          recordTimingFlag(username, wpm, accuracy, timing).catch(() => {});
        }
      }
    }

    const place = room.finishedOrder.length + 1;
    // Include display info directly here rather than making clients look it
    // up separately -- this is the exact same data already stored on this
    // player/bot when they joined the room, just carried along with their
    // result instead of needing a separate cross-reference the client has
    // to keep in sync.
    const finisherData = room.players.get(username) || {};
    const displayName = finisherData.displayName || "";
    const guildTag = finisherData.guildTag || "";
    const guildColor = finisherData.guildColor || "";
    const titleText = finisherData.titleText || "";
    const titleRarity = finisherData.titleRarity || "";

    room.finishedOrder.push({ username, wpm, accuracy, timeMs, place, displayName, guildTag, guildColor, titleText, titleRarity });

    broadcastToRoom(room, { type: "opponent_finished", username, wpm, accuracy, timeMs, place, displayName, guildTag, guildColor, titleText, titleRarity }, username);

    if (room.finishedOrder.length >= room.players.size) {
      broadcastToRoom(room, { type: "race_complete", placements: room.finishedOrder }, null);
      room.players.forEach((p, uname) => {
        p.ws.roomId = null;
        if (p.isBot) activeBotUsernames.delete(uname);
      });
      rooms.delete(room.id);
    }
  }

  wss.on("connection", (ws) => {
    ws.isAlive = true;
    ws.on("pong", () => { ws.isAlive = true; });

    ws.on("message", (raw) => {
      let msg;
      try { msg = JSON.parse(raw); } catch (e) { return; }

      if (msg.type === "join_race") {
        if (!msg.username) return;
        if (ws.roomId) return; // already in a room on this connection
        const uname = String(msg.username).slice(0, 30).toLowerCase();
        // If this username already has an active connection in a race, kick
        // the old one before allowing the new join — this handles tab refresh.
        // If the old connection is still alive and racing, reject the new one.
        if (activePlayers.has(uname)) {
          const existingWs = activePlayers.get(uname);
          if (existingWs.readyState === WebSocket.OPEN && existingWs.roomId) {
            // Old connection is still active in a race — reject the new join
            send(ws, { type: "error", message: "already_in_race" });
            ws.close();
            return;
          } else {
            // Old connection is dead or not in a room — clean it up
            activePlayers.delete(uname);
          }
        }
        activePlayers.set(uname, ws);
        joinRoom(ws, uname, msg.carId || "starter_car", msg.recentWpm || DEFAULT_WPM, msg.displayName || "", msg.guildTag || "", msg.guildColor || "", msg.titleText || "", msg.titleRarity || "", msg.nameTag || "");
        return;
      }

      if (msg.type === "progress") {
        const room = rooms.get(ws.roomId);
        if (!room || !room.locked) return;
        // Record the SERVER-observed arrival time of each progress update.
        // The client controls charsTyped, but it cannot control when the
        // server actually receives the message -- so the spacing between
        // these timestamps is an un-fakeable window into the real typing
        // cadence. A human bursts and pauses; an autotyper ticks at a
        // near-constant interval. We analyze this at finish.
        const playerData = room.players.get(ws.username);
        if (playerData && !playerData.isBot) {
          if (!playerData.progressSamples) playerData.progressSamples = [];
          // Cap the array so a flood of progress spam can't grow memory
          // unbounded -- 400 samples is far more than any real race needs.
          if (playerData.progressSamples.length < 400) {
            playerData.progressSamples.push({
              at: Date.now(),
              chars: typeof msg.charsTyped === "number" ? msg.charsTyped : 0,
            });
          }
        }
        broadcastToRoom(room, {
          type: "opponent_progress",
          username: ws.username,
          charsTyped: msg.charsTyped,
          wpm: msg.wpm,
        }, ws.username);
        return;
      }

      if (msg.type === "finished") {
        const room = rooms.get(ws.roomId);
        finishPlayerRace(room, ws.username, msg.wpm, msg.accuracy, msg.timeMs, false);
        return;
      }
    });

    ws.on("close", () => {
      // Remove from active players tracker
      if (ws.username && activePlayers.get(ws.username) === ws) {
        activePlayers.delete(ws.username);
      }

      if (!ws.roomId) return;
      const room = rooms.get(ws.roomId);
      if (!room) return;

      room.players.delete(ws.username);
      broadcastToRoom(room, { type: "opponent_left", username: ws.username }, null);

      // Clean up fully if nobody's left, OR if the only ones left are
      // bots -- a room with just a bot in it and no real player watching
      // has no reason to keep running.
      if (room.players.size === 0 || !roomHasRealPlayer(room)) {
        room.players.forEach((p, uname) => { if (p.isBot) activeBotUsernames.delete(uname); });
        if (room.joinTimer) clearTimeout(room.joinTimer);
        if (room.botCheckTimer) clearTimeout(room.botCheckTimer);
        if (openRoom === room) openRoom = null;
        rooms.delete(room.id);
      }
    });
  });

  const heartbeat = setInterval(() => {
    wss.clients.forEach((ws) => {
      if (ws.isAlive === false) return ws.terminate();
      ws.isAlive = false;
      ws.ping();
    });
  }, 30000);
  wss.on("close", () => clearInterval(heartbeat));

  return wss;
}

module.exports = { makeRaceServer, setDb };
