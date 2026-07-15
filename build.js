/**
 * build.js — runs on Render at deploy time (Build Command: npm install && node build.js)
 *
 * Takes public/zebra_type.html (the readable, commented source that lives in
 * the repo), minifies its three inline <script> blocks into one file, and
 * rewrites the HTML to load that file instead.
 *
 * IMPORTANT: this only rewrites files inside the BUILD CONTAINER. The copy in
 * your repo is never touched, so the readable source is always safe in git and
 * you keep editing/pasting exactly one file like you do today.
 *
 * To roll back: set the Render Build Command back to `npm install` and
 * redeploy. The readable file is served again immediately. Nothing to undo.
 *
 * If anything here fails it exits non-zero, which fails the deploy and leaves
 * the previous working version running. Failing loudly is deliberate: a broken
 * build must never quietly ship a broken game.
 */
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { minify } = require("terser");

const PUBLIC_DIR = path.join(__dirname, "public");
const HTML_PATH = path.join(PUBLIC_DIR, "zebra_type.html");

// Matches only <script> with NO attributes -- which is exactly the three real
// blocks. The anticheat's doc comments contain `<script src="..."><\/script>`
// examples, but those have attributes and their closing tags are escaped, so
// they can't be picked up here.
const SCRIPT_RE = /<script>([\s\S]*?)<\/script>/g;

const EXPECTED_BLOCKS = 3;

async function build() {
  if (!fs.existsSync(HTML_PATH)) throw new Error("missing " + HTML_PATH);
  const src = fs.readFileSync(HTML_PATH, "utf8");

  const blocks = [];
  let m;
  while ((m = SCRIPT_RE.exec(src)) !== null) {
    blocks.push({ full: m[0], code: m[1] });
  }

  // A guard, not a formality: if someone adds or removes a script block, the
  // assumptions below (ordering, global scope) need re-checking by a human
  // rather than silently producing a subtly broken bundle.
  if (blocks.length !== EXPECTED_BLOCKS) {
    throw new Error(
      "expected " + EXPECTED_BLOCKS + " inline <script> blocks, found " + blocks.length +
      " — refusing to guess. Check public/zebra_type.html."
    );
  }

  // The three blocks share one global scope and run in order, so concatenating
  // them in the same order is equivalent. Semicolons between them guard against
  // a missing trailing semicolon joining two statements together.
  const combined = blocks.map((b) => b.code).join("\n;\n");

  const result = await minify(combined, {
    ecma: 2020,
    // toplevel:false is load-bearing. Blocks 0 and 1 (anticheat + device
    // fingerprint) define their API at the top level -- AntiCheat, and what
    // the game calls into. Mangling those would break the game's references
    // AND break `AntiCheat.verdict()` in the console, which is the only way
    // to debug the anticheat on a live account. The 880KB game block is
    // IIFE-wrapped, so all of ITS internals still get mangled -- that's the
    // overwhelming majority of the code and where the benefit actually is.
    mangle: { toplevel: false },
    compress: {
      // Keep console.* -- the anticheat logs through it and it's how the
      // owner inspects live behaviour.
      drop_console: false,
      drop_debugger: true,
      passes: 1,
    },
    format: { comments: false },
  });

  if (result.error) throw result.error;
  const code = result.code;
  if (!code || code.length < 50000) {
    throw new Error("minified output is implausibly small (" + (code ? code.length : 0) + " bytes) — aborting");
  }

  // Content-hashed filename so browsers can never serve a stale bundle after
  // a deploy, and so the file can be cached hard.
  const hash = crypto.createHash("sha256").update(code).digest("hex").slice(0, 10);
  const jsName = "game." + hash + ".js";
  fs.writeFileSync(path.join(PUBLIC_DIR, jsName), code, "utf8");

  // Replace from the END backwards so earlier matches stay valid: blocks 1 and
  // 2 are removed, and block 0 (the first, and therefore the right execution
  // point) becomes the single external script tag.
  let out = src;
  for (let i = blocks.length - 1; i >= 1; i--) out = out.replace(blocks[i].full, "");
  out = out.replace(blocks[0].full, '<script src="/' + jsName + '"></script>');

  if (out.indexOf("<script>") !== -1) {
    throw new Error("an inline <script> survived the rewrite — aborting rather than shipping a double-executing page");
  }

  // Externalise the stylesheet too. Nothing depends on CSS execution order the
  // way scripts do, so this is a safe lift -- and it's what takes view-source
  // from "34KB of stylesheet" down to essentially an empty page. It also lets
  // the browser cache the CSS separately from the HTML.
  const styleMatches = [...out.matchAll(/<style[^>]*>([\s\S]*?)<\/style>/g)];
  if (styleMatches.length === 1) {
    const css = styleMatches[0][1];
    const cssHash = crypto.createHash("sha256").update(css).digest("hex").slice(0, 10);
    const cssName = "style." + cssHash + ".css";
    fs.writeFileSync(path.join(PUBLIC_DIR, cssName), css, "utf8");
    out = out.replace(styleMatches[0][0], '<link rel="stylesheet" href="/' + cssName + '">');
    console.log("[build] " + cssName + " (" + kb(Buffer.byteLength(css, "utf8")) + ")");
  } else if (styleMatches.length > 1) {
    // More than one means the assumption above needs a human to re-check
    // rather than this quietly guessing at ordering.
    throw new Error("expected 0 or 1 <style> blocks, found " + styleMatches.length + " — refusing to guess.");
  }

  fs.writeFileSync(HTML_PATH, out, "utf8");

  const before = Buffer.byteLength(src, "utf8");
  const after = Buffer.byteLength(out, "utf8") + Buffer.byteLength(code, "utf8");
  console.log("[build] " + jsName);
  console.log("[build] html " + kb(before) + " -> html " + kb(Buffer.byteLength(out, "utf8")) + " + js " + kb(Buffer.byteLength(code, "utf8")));
  console.log("[build] total " + kb(before) + " -> " + kb(after) + " (" + pct(before, after) + ")");
}

function kb(n) { return Math.round(n / 1024) + "KB"; }
function pct(a, b) {
  const d = Math.round(((a - b) / a) * 100);
  return (d >= 0 ? "-" + d : "+" + Math.abs(d)) + "%";
}

build().catch((e) => {
  console.error("[build] FAILED:", e && e.message ? e.message : e);
  console.error("[build] deploy aborted — the previous version stays live.");
  process.exit(1);
});
