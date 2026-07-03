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

// Load passage texts from shared storage key "race_passages".
// Uses a short cache so rapid room creation doesn't hammer the DB,
// but always reloads if the cache is stale so admin changes take effect.
async function loadPassageTexts() {
  if (!db) return;
  const now = Date.now();
  if (passageTexts.length > 0 && now - passageTextsLastLoaded < PASSAGE_CACHE_MS) return;
  try {
    const row = db.get("system", "race_passages", true);
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
      list.push({ username, carId: p.carId, displayName: p.displayName || "", guildTag: p.guildTag || "", guildColor: p.guildColor || "", titleText: p.titleText || "", titleRarity: p.titleRarity || "" });
    });
    return list;
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
    });
  }

  function joinRoom(ws, username, carId, recentWpm, displayName, guildTag, guildColor, titleText, titleRarity) {
    let room = openRoom;
    if (!room || room.locked || room.players.size >= ROOM_SIZE) {
      const roomId = crypto.randomBytes(6).toString("hex");
      room = { id: roomId, players: new Map(), locked: false, joinTimer: null, finishedOrder: [] };
      rooms.set(roomId, room);
      openRoom = room;
      room.joinTimer = setTimeout(() => lockAndStartCountdown(room), JOIN_WINDOW_MS);
    }

    room.players.set(username, { ws, carId, recentWpm: recentWpm || DEFAULT_WPM, displayName: displayName || "", guildTag: guildTag || "", guildColor: guildColor || "", titleText: titleText || "", titleRarity: titleRarity || "" });
    ws.roomId = room.id;
    ws.username = username;

    send(ws, { type: "room_joined", roomId: room.id, opponentsSoFar: opponentList(room, username) });
    broadcastToRoom(room, { type: "room_joined", roomId: room.id, opponentsSoFar: opponentList(room, ws.username) }, username);

    if (room.players.size >= ROOM_SIZE && !room.locked) {
      clearTimeout(room.joinTimer);
      // Small delay so all players receive room_joined before race_starting,
      // ensuring the full countdown plays on every client.
      room.joinTimer = setTimeout(() => lockAndStartCountdown(room), 1000);
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
        joinRoom(ws, uname, msg.carId || "starter_car", msg.recentWpm || DEFAULT_WPM, msg.displayName || "", msg.guildTag || "", msg.guildColor || "", msg.titleText || "", msg.titleRarity || "");
        return;
      }

      if (msg.type === "progress") {
        const room = rooms.get(ws.roomId);
        if (!room || !room.locked) return;
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
        if (!room || !room.locked) return;
        if (room.finishedOrder.some((f) => f.username === ws.username)) return;

        // Server-side WPM sanity check — the server knows the passage
        // length assigned to this player and when the race started, so
        // it can compute the maximum possible WPM and reject manipulated
        // results that exceed what any human could physically type.
        const playerData = room.players.get(ws.username);
        if (playerData && room.startsAt && msg.timeMs > 0) {
          const passageLen = playerData.passage ? playerData.passage.length : 0;
          if (passageLen > 0) {
            const elapsedMinutes = msg.timeMs / 60000;
            const impliedWpm = Math.round((passageLen / 5) / elapsedMinutes);
            const SERVER_WPM_CAP = 350; // matches client cap
            if (impliedWpm > SERVER_WPM_CAP) {
              // Clamp to the cap rather than rejecting outright — legitimate
              // fast typists near the boundary shouldn't be penalised, and
              // a cheater getting capped at 350 is far less harmful than
              // having their manipulated result accepted.
              msg.wpm = SERVER_WPM_CAP;
              console.warn(`[race] WPM clamped for ${ws.username}: implied ${impliedWpm} → ${SERVER_WPM_CAP}`);
            }
          }
        }
        const place = room.finishedOrder.length + 1;
        room.finishedOrder.push({ username: ws.username, wpm: msg.wpm, accuracy: msg.accuracy, timeMs: msg.timeMs, place });

        broadcastToRoom(room, {
          type: "opponent_finished",
          username: ws.username,
          wpm: msg.wpm,
          accuracy: msg.accuracy,
          timeMs: msg.timeMs,
          place,
        }, ws.username);

        if (room.finishedOrder.length >= room.players.size) {
          broadcastToRoom(room, { type: "race_complete", placements: room.finishedOrder }, null);
          room.players.forEach((p) => { p.ws.roomId = null; });
          rooms.delete(room.id);
        }
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

      if (room.players.size === 0) {
        if (room.joinTimer) clearTimeout(room.joinTimer);
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
