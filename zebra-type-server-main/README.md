# Zebra Type — Multiplayer Server

This is the backend for Zebra Type: a small Node.js server that handles
account/garage/guild/etc. storage and live multiplayer race matchmaking.

**Important: this server has zero copies of your game's HTML/CSS/JS in
it.** It only stores data and relays WebSocket messages. That means
updating your game later — new features, bug fixes, anything in
zebra_type.html — never requires touching or redeploying this server.
You just edit the HTML file and re-upload it wherever you're hosting
it. See "Updating the game later" below.

## What's in here

```
server/
  src/
    db.js               # SQLite key-value store (the actual storage engine)
    storageRoutes.js     # REST API exposing that store
    race.js               # WebSocket matchmaking + live race rooms
    server.js             # entry point, wires the above together
  public/
    zebra_type.html      # your game, ready to run -- SERVER_URL auto-detects this server
  docs/
    DEPLOYMENT.md        # step-by-step: get this running on the internet
    TESTING_NOTES.md     # what was verified working, and how
  package.json
  .env.example
```

(There used to be a CLIENT_STORAGE_PATCH.txt here with manual edits to
make in your game file — that patch is now already applied directly
inside zebra_type.html. You don't need to do anything to the game file
except set one line, covered below.)

## Quick start (running it locally first)

Before deploying anywhere, it's worth running this on your own machine
once just to see it work:

```
cd server
npm install
npm start
```

You should see:
```
Server listening on port 3001
  Game:       http://localhost:3001/zebra_type.html
  HTTP API:   http://localhost:3001/api
  WebSocket:  ws://localhost:3001/race
```

Visit `http://localhost:3001/health` in a browser — `{"ok":true,...}`
means the server's working. Visit `http://localhost:3001/zebra_type.html`
and you've got the actual game running against it, no extra setup —
the game's `SERVER_URL` auto-detects whatever server it's being served
from, so this just works.

## Connecting your game to it

If you keep `public/zebra_type.html` where it is and host it from this
same server, nothing to do — it auto-detects the server it's being
served from.

If you want to host the HTML file somewhere else entirely (a separate
static host — see "Hosting the game file" in docs/DEPLOYMENT.md), open
`public/zebra_type.html` and find this near the top of the `<script>`
section:

```js
var SERVER_URL = window.location.origin;
```

Replace it with your deployed server's actual URL, e.g.:

```js
var SERVER_URL = "https://zebra-type-server.onrender.com";
```

Either way, that one line controls everything: accounts, garages,
guilds, the wheel, achievements, friends, and live multiplayer racing
all go through whatever it resolves to.

## Updating the game later

Because the server and the game file are completely separate:

1. Make whatever changes you want to `public/zebra_type.html` (new
   features, car catalog changes, anything) — or replace it entirely
   with a newer version of the file.
2. If you kept `SERVER_URL` as `window.location.origin` (the default),
   there's nothing else to do — it'll keep auto-detecting correctly. If
   you changed it to a fixed URL because you're hosting the HTML
   separately, just make sure that line is still pointing at the right
   place.
3. Redeploy/re-upload — for the same-server setup, just push the
   updated `public/zebra_type.html` to wherever you deployed this
   server (e.g. commit + push to the GitHub repo Render is watching).
   For a separately-hosted HTML file, re-upload it to that static host.

No server restart of the storage/matchmaking logic is needed, no
database changes, nothing in `src/` is touched. Every player's account,
coins, cars, etc. stay exactly as they were, since all of that lives in
this server's database, not in the HTML file at all.

The only time you'd ever need to touch the server's actual code is if
you change something about how data is stored or how matchmaking works
— editing `src/db.js`, `src/storageRoutes.js`, or `src/race.js`
specifically, not just editing the game.

## Where to go next

1. **docs/DEPLOYMENT.md** — get this server live on the internet
   (Render, Railway, or Fly.io, all with free tiers to start), and how
   to host zebra_type.html itself
2. **docs/TESTING_NOTES.md** — what's actually been verified to work

## The short version of how this fits together

Your game routes every storage operation — accounts, garages, guilds,
achievements, the wheel, friends, everything — through four functions
(shimGet, shimSet, shimList, shimDelete) that are already wired to call
this server's REST API. Live multiplayer racing uses a separate
WebSocket connection (src/race.js) for the parts that need the server
to push updates in real time — seeing an opponent's typing progress
update on your screen as they type, not just when you ask. The flow:
pressing Race always works, whether or not anyone else is online —
you're placed in a room immediately, it stays open to other joiners for
3 seconds, then locks and a synced 5-second countdown starts for
whoever's in it (1 to 4 players). Both pieces are fully wired into the
game already and tested working end-to-end against a real running
instance of this server.
