# Deploying Zebra Type's Server

This covers getting the server live on the internet, then pointing your
game at it, and how updates work afterward.

1. Deploy the server (pick one host below)
2. Point `zebra_type.html` at it (one line, already wired up)
3. Host the game file itself somewhere people can open it

---

## Part 1 — Deploy the server

All three options below have free tiers good enough to start with, and
all three work the same way: push this folder to them, they run
`npm install && npm start`, and give you a public URL.

I'd recommend **Render** if you've never deployed a server before — it
has the gentlest setup. **Railway** is just as easy and often a bit
faster to spin up. **Fly.io** is the most flexible but has the steepest
learning curve, so it's better as a second move once you outgrow the
others.

### Option A: Render (recommended to start)

1. Push this `server/` folder to a GitHub repository (Render deploys from
   GitHub, not by direct file upload). If you don't already use git:
   ```
   cd server
   git init
   git add .
   git commit -m "Initial server"
   ```
   Then create a new repo on github.com and follow its instructions to
   push (`git remote add origin ...`, `git push -u origin main`).

2. Go to https://render.com, sign up, click **New +** → **Web Service**.

3. Connect your GitHub account and select the repo.

4. Render will detect it's a Node project. Set:
   - **Build Command:** `npm install`
   - **Start Command:** `npm start`
   - **Instance Type:** Free

5. Add a **persistent disk** (Render calls this in the same setup page,
   or under the service's "Disks" tab afterward) — without this, your
   SQLite database gets wiped every time Render restarts the server,
   which happens periodically on the free tier:
   - Mount path: `/data`
   - Then add an environment variable: `DB_PATH` = `/data/data.sqlite`

6. Click **Create Web Service**. First deploy takes a few minutes.

7. Once live, Render gives you a URL like
   `https://zebra-type-server.onrender.com` — that's your `SERVER_URL`
   for Part 2 below.

8. Test it: visit `https://your-url.onrender.com/health` in a browser —
   you should see `{"ok":true,"time":...}`.

**Free tier note:** Render's free web services "spin down" after 15
minutes of no traffic and take ~30-60 seconds to wake back up on the
next request. Fine for testing with friends; for a real launch, either
upgrade to a paid instance ($7/mo as of writing) or accept that the
first visitor after a quiet period waits a bit.

### Option B: Railway

1. Push this folder to GitHub (same as step 1 above).
2. Go to https://railway.app, sign up, **New Project** → **Deploy from
   GitHub repo**, pick your repo.
3. Railway auto-detects Node and runs `npm install && npm start`
   automatically — no config needed for that part.
4. Add a volume for the database: in the service settings, **Volumes**
   → mount at `/data`, then set the `DB_PATH` env var to
   `/data/data.sqlite` (Settings → Variables).
5. Under **Settings** → **Networking**, click **Generate Domain** to get
   a public URL.
6. Test `/health` the same way as above.

Railway's free tier is usage-based credit rather than always-free, so
check current pricing before committing — it's generally cheap for a
small project but worth knowing it's not unlimited.

### Option C: Fly.io

More setup, but no spin-down/sleep behavior even on the free allowance,
and more control. Requires their CLI:

1. Install the CLI: https://fly.io/docs/flyctl/install/
2. `fly auth login`
3. From inside the `server/` folder: `fly launch` — it'll detect Node,
   ask a few questions (region, etc.), and generate a `fly.toml`. Say no
   to deploying immediately if it asks, so you can add storage first.
4. Add a persistent volume:
   ```
   fly volumes create zebra_data --size 1
   ```
5. Edit the generated `fly.toml` to mount it and set the DB path:
   ```toml
   [mounts]
     source = "zebra_data"
     destination = "/data"

   [env]
     DB_PATH = "/data/data.sqlite"
   ```
6. `fly deploy`
7. `fly status` shows your public URL (`https://your-app.fly.dev`).

---

## Part 2 — Point the game at your server

`public/zebra_type.html` already auto-detects whatever server it's
served from (`SERVER_URL = window.location.origin`). If you're using
the same-server hosting option in Part 3 below, there's nothing to do
here — skip straight to Part 3.

Only if you want to host the HTML file somewhere OTHER than this
server do you need to change anything: open `public/zebra_type.html`,
find this near the top of the `<script>` section:

```js
var SERVER_URL = window.location.origin;
```

Replace it with your deployed server's URL from Part 1, e.g.:

```js
var SERVER_URL = "https://zebra-type-server.onrender.com";
```

Either way, accounts, garages, guilds, achievements, the wheel,
friends, and live multiplayer racing all use this one value.

---

## Part 3 — Host the game file

`zebra_type.html` already lives in `public/` and this server already
serves it (see `src/server.js`) — so if you deploy this whole folder as-is
(Part 1), your game is automatically live at the same URL as your API,
e.g. `https://zebra-type-server.onrender.com/zebra_type.html`. No extra
step needed for this option.

If you'd rather host the HTML file somewhere else (a separate static
host — Netlify, Vercel, GitHub Pages, Cloudflare Pages, all free for a
single static file): copy `public/zebra_type.html` out, upload it there
instead, and follow Part 2 above to point `SERVER_URL` at this server's
URL instead of relying on auto-detection.

Either way works the same for players — the only thing that matters is
where `SERVER_URL` (or its auto-detected value) ends up pointing.

---

## Updating the game after you've already deployed

This is the part that's easy precisely because the server and the game
file are two separate things. Whenever you (or I) change
zebra_type.html — new feature, balance tweak, bug fix, anything —
getting that change live is just:

1. Take the new zebra_type.html and put it in `public/` (replacing the
   old one), or wherever you're hosting it separately.
2. If `SERVER_URL` is still `window.location.origin` (the default),
   there's nothing else to check. If you set it to a fixed URL because
   you're hosting the HTML separately, make sure that line is still
   correct.
3. Push the update — for the same-server setup, commit and push to
   whatever repo your host (Render/Railway/Fly.io) is watching, and it
   redeploys automatically. For a separately-hosted HTML file,
   re-upload it to that static host.

You do **not** need to touch the database, or change anything in
`src/`. Every player's account/coins/cars are stored server-side and
are completely unaffected by swapping the HTML file. The only
exception: if a change specifically needs new server-side behavior (a
new storage shape the server doesn't know about, a change to the
matchmaking rules itself), that would mean editing something in `src/`
too — but day-to-day game updates don't need that.

---

## Verifying everything works after deploying

1. Visit `your-server-url/health` → should return `{"ok":true,...}`
2. Open your hosted game file, register a new account
3. Refresh the page, log back in with that account — if your stats and
   garage are still there, storage is working
4. Open the game in two different browsers (or one normal + one private
   window) and register two different accounts — each should only see
   their own private data, but both should appear on the leaderboard
   (shared data)
5. Have both accounts press Race within a few seconds of each other —
   they should land in the same race together (see TESTING_NOTES.md for
   what this was already verified to do)

---

## Before this is fully public

See the `SECURITY_NOTE` comment at the top of `src/server.js` — the
current auth model (an `x-owner` header) is fine for a private playtest
with friends, but isn't a real verified session. Before opening this up
broadly, that's the first thing to harden.
