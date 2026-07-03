# What's Been Tested

Everything below was actually run, not just written and assumed correct.
Useful context if something breaks later and you're trying to figure out
whether it's a regression or was never quite right.

## Storage API (src/storageRoutes.js + src/db.js)

Tested via direct HTTP requests against a running server:
- SET then GET a private key round-trips correctly
- GET a private key as a different owner correctly returns 404
  (private data isolation works)
- SET then GET a shared key from a different owner correctly succeeds
  (shared data is visible to everyone, as intended)
- LIST with a prefix filter returns only matching keys
- DELETE removes the key; subsequent GET returns 404

Also tested with the WASM SQLite fallback specifically (since
better-sqlite3 needs a C++ build toolchain that wasn't available in the
sandbox this was built in) -- both drivers share the same db.js
interface and the tests above passed identically on the fallback. On a
real server with normal build tools, npm install will get you the
faster native driver automatically; the optional-dependency fallback is
there so the server still runs even somewhere without a compiler.

## WebSocket matchmaking (src/race.js)

The flow: press Race, you're placed in a room immediately (a new one, or
one still open to joiners). That room accepts new joiners for 3 seconds
(JOIN_WINDOW_MS), then locks -- whoever's in it races together, from 1
up to 4 players. A synced 5-second countdown (COUNTDOWN_MS) starts the
instant the room locks. Racing always happens; there's no waiting
forever for a fixed headcount.

Tested with real WebSocket client connections, not mocked:
- A single player joins and nobody else does: room_joined fires
  immediately, race_starting fires at exactly the 3-second mark with 0
  opponents -- confirms solo racing always proceeds rather than hanging
- Two players join within the 3-second window (1.5s apart): both land
  in the same room, get the same passage, the same roomId, and the
  exact same startsAt timestamp; the player who joined first also gets
  a live room_joined update the moment the second player joins, so a
  waiting screen can show opponents appearing in real time
- A player who joins AFTER another player's 3-second window already
  closed correctly starts a brand new room, not the locked one
- 4 players joining within ~150ms of each other all land in the same
  room AND the room locks immediately once full, rather than waiting
  out the rest of the 3-second window unnecessarily
- progress messages sent before the room locks are correctly dropped
  (not broadcast to anyone) -- confirmed with precise timing, since an
  earlier looser timing test gave a misleading result before being
  corrected
- progress messages sent after the room locks are correctly broadcast
  to the other player(s) in the room
- finished messages are correctly broadcast as opponent_finished with
  the right place, and once everyone in the room has finished,
  race_complete fires with the full ordered placement list
- Disconnect handling exists (removes from the room, notifies remaining
  room members, cleans up an empty room and its join timer) but wasn't
  exercised by an automated test -- worth a manual check before relying
  on it for a real match

## Full client integration (zebra_type.html)

This is the test that matters most: the actual game file, run against
a live instance of this server, driving the real UI rather than
calling functions directly:

- Filled out and submitted the real signup form -- account created,
  confirmed both client-side (state.user set, screen moved to
  dashboard) and server-side (queried the database directly and found
  the account)
- Logged out via the real nav bar button -- state.user correctly
  cleared, returned to the auth screen
- Logged back in with the same credentials via the real login form --
  pulled the exact same account back down from the server
- Two simulated players raced against each other through the real
  server: pressed Race within a few seconds of each other, landed in
  the same room, got the same passage, typed it out, and both saw
  correct final placements (1st/2nd) with coin rewards matching their
  placement
- Specifically verified the public/zebra_type.html + server.js static
  hosting setup (the "run the server, open the URL, everything just
  works" path): fetched the game AS SERVED by a real running instance
  of this server (not a local file), confirmed SERVER_URL correctly
  auto-resolves via window.location.origin with no manual edits
  needed, registered an account through the real form, and confirmed
  it was actually saved server-side

This confirms the integration works end-to-end, not just in isolation.

### Two environment-only gotchas hit during testing, not real bugs

Both only came up because automated browser-less testing (Node +
jsdom) doesn't have every API a real browser has by default -- neither
applies to an actual person using a real browser:

1. jsdom's window doesn't have fetch unless you add it -- real browsers
   always do.
2. jsdom's window.crypto exists but its .subtle (used by the game's
   password hashing) isn't wired up by default -- real browsers always
   have it.

Mentioned here only so if you ever try to automate-test this game
yourself in a headless/non-browser environment, you'll know to add
those two polyfills rather than chase a phantom bug.

## What was NOT tested

- A real deployment on Render/Railway/Fly.io itself (the deployment
  steps in DEPLOYMENT.md are written from how each platform's standard
  Node deployment flow works, but weren't run against a live account on
  each -- worth following along carefully the first time and comparing
  against their current dashboard, since hosting platforms occasionally
  tweak their UI)
- Load/stress testing (how many concurrent players this setup can
  actually handle before the free tier struggles)
- The disconnect-mid-race path in race.js (code is there, logic looks
  right, but no automated test exercised it)
