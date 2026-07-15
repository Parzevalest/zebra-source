// moderation.js — Name auto-moderation for Panda Type.
//
// Zero external dependencies, same as security.js.
//
// WHAT THIS REPLACES:
// The old filter lived in zebra_type.html only, which meant it was advisory:
// anyone POSTing straight to /api/register skipped it entirely. It also did a
// plain substring match over a hardcoded list, which rejected Peacock,
// Hancock, Dickens, Dickinson, Cockpit, Cocktail, GrapeFan, Spicy and Shitake
// -- 14 out of 21 ordinary names in testing -- while missing "fuuuck",
// fullwidth "ｆｕｃｋ" and anything written in Cyrillic.
//
// THE TWO-LIST IDEA (this is the important part):
// A single list can't work, because the same word needs different treatment
// depending on how it's used:
//   * Severe slurs must be caught ANYWHERE in a name -- "xXn1ggerXx".
//   * Mild words like "cock" must only be caught as a WHOLE name -- otherwise
//     Peacock, Hancock and Cockburn (all real surnames) get rejected.
// So: blockContains matches anywhere, blockExact matches only the full name.
//
// THE ALLOW LIST:
// Even careful lists collide. Collapsing repeated letters turns "nigger" into
// "niger", which then matches "Nigeria". Rather than give up the collapsing
// (which is what catches "fuuuck"), allowed words are REMOVED from the name
// before blocked words are searched for. So:
//   "nigeria"     -> remove "nigeria" -> ""      -> clean
//   "peacock"     -> remove "peacock" -> ""      -> clean
//   "peacockfuck" -> remove "peacock" -> "fuck"  -> caught
// The allowance is for the innocent word, not a free pass for the whole name.

// Cyrillic and Greek characters that are visually identical (or near enough)
// to Latin ones. Without this, a name written in Cyrillic sails past every
// list. This matters more since premium display names allow non-Latin scripts.
const HOMOGLYPHS = {
  "а":"a","в":"b","е":"e","к":"k","м":"m","н":"h","о":"o","р":"p","с":"c",
  "т":"t","у":"y","х":"x","і":"i","ѕ":"s","ј":"j","ԁ":"d","ɡ":"g","ь":"b",
  "α":"a","ο":"o","ε":"e","ι":"i","κ":"k","ν":"v","ρ":"p","τ":"t","υ":"u",
  "χ":"x","ω":"w","β":"b","γ":"y","η":"n","μ":"m","σ":"o","ϲ":"c",
};

const LEET = { "0":"o","1":"i","3":"e","4":"a","5":"s","7":"t","8":"b","9":"g","@":"a","$":"s","!":"i","+":"t","(":"c" };

// Reduces a name to a bare lowercase a-z skeleton for comparison. Everything
// here exists to defeat a specific evasion:
//   NFKD + mark strip : "ｆｕｃｋ" and "fúck" -> "fuck"
//   homoglyph map     : Cyrillic "хуй" -> latin letters
//   leet map          : "sh1t" -> "shit"
//   strip non-letters : "f_u_c_k" and "f.u.c.k" -> "fuck"
//   collapse runs     : "fuuuck" -> "fuck"
//
// Collapsing runs is why the allow list is necessary rather than optional:
// it also turns "niger" and "nigger" into the same skeleton. That's the
// deliberate trade -- catch the evasion, then carve back the false positives.
function normalize(input) {
  let t = String(input == null ? "" : input).toLowerCase();

  // Fold fullwidth forms, ligatures and accents down to plain ASCII.
  try { t = t.normalize("NFKD").replace(/\p{M}/gu, ""); } catch (e) { /* older runtime: skip */ }

  let out = "";
  for (const ch of t) {
    if (HOMOGLYPHS[ch]) { out += HOMOGLYPHS[ch]; continue; }
    if (LEET[ch]) { out += LEET[ch]; continue; }
    out += ch;
  }

  out = out.replace(/[^a-z]/g, "");     // drop spaces, digits, punctuation
  out = out.replace(/(.)\1+/g, "$1");   // "fuuuck" -> "fuck"
  return out;
}

// Your existing list, split by how each term actually behaves.
//
// A term belongs in blockExact ONLY if an ordinary English word or surname
// contains it. Everything else goes in blockContains, or evasions like
// "xXfuckXx" walk straight through.
//   cock -> Peacock, Hancock, Cockburn, Cockpit, Cocktail
//   dick -> Dickens, Dickinson
//   rape -> grape, drapery, scrape
//   spic -> spicy
//   fag  -> Fagan
//   dyke -> Van Dyke
// Nothing innocent contains "fuck", "cunt" or "nigger", so those match
// anywhere -- with the allow list below carving out the real collisions.
const DEFAULT_CONFIG = {
  enabled: true,
  blockContains: [
    "fuck", "shit", "bitch", "cunt", "nigger", "nigga", "faggot", "retard",
    "whore", "slut", "chink", "kike", "tranny", "pedo", "molest", "asshole",
    "piss", "pussy", "twat", "rapist",
    // Phrases: separators are stripped before matching, so "kill your self"
    // and "kill_yourself" both reduce to this.
    "killyourself", "kys",
  ],
  blockExact: [
    "fag", "dyke", "spic", "rape", "cock", "dick",
  ],
  // Real collisions with the lists above. Each one is a word that genuinely
  // contains a blocked term:
  //   scunthorpe -> cunt   (the original, famous case)
  //   nigeria    -> nigger (once repeated letters are collapsed)
  //   shitake    -> shit
  //   therapist  -> rapist
  allow: [
    "scunthorpe", "nigeria", "shitake", "shiitake", "therapist", "therapists",
    // Not strictly needed while the words above sit in blockExact, but they
    // keep these names safe if you ever move one to "blocked anywhere".
    "peacock", "cockpit", "cocktail", "cockburn", "hancock", "woodcock",
    "dickens", "dickinson", "dickson", "grape", "grapes", "drapery",
    "scrape", "scraper", "spicy", "vandyke",
  ],
};

// Deep-ish clone so callers can't mutate the defaults by accident.
function defaultConfig() {
  return {
    enabled: DEFAULT_CONFIG.enabled,
    blockContains: DEFAULT_CONFIG.blockContains.slice(),
    blockExact: DEFAULT_CONFIG.blockExact.slice(),
    allow: DEFAULT_CONFIG.allow.slice(),
  };
}

// Accepts whatever is stored in the automod_config key and returns something
// safe to use. A malformed or half-written config must never crash a signup,
// and must never silently disable moderation either -- so anything unusable
// falls back to the defaults rather than to "allow everything".
function sanitizeConfig(raw) {
  const obj = (raw && typeof raw === "object") ? raw : null;

  // Resolved first and applied to every return path below. An earlier version
  // computed this inside the object literal, so the "fall back to defaults"
  // branch quietly replaced enabled:false with the default enabled:true --
  // the off switch didn't switch anything off.
  const enabled = !(obj && obj.enabled === false);

  if (!obj) { const d = defaultConfig(); d.enabled = enabled; return d; }

  // An admin who has never touched this tab has no lists stored. That's not a
  // decision to moderate nothing -- it means "use the defaults". Deliberately
  // emptying the lists IS a decision, and is honoured, because the keys are
  // then present but empty.
  const hasLists = obj.blockContains !== undefined || obj.blockExact !== undefined;
  if (!hasLists) { const d = defaultConfig(); d.enabled = enabled; return d; }

  const arr = (v) => Array.isArray(v) ? v.filter((x) => typeof x === "string" && x.trim()).map((x) => x.trim()) : [];
  return {
    enabled,
    blockContains: arr(obj.blockContains),
    blockExact: arr(obj.blockExact),
    allow: arr(obj.allow),
  };
}

// Is the match at [start,end) sitting entirely inside an occurrence of an
// allowed word?
//
// This replaced an earlier approach that simply DELETED allowed words from the
// name before searching. That was subtly broken: "nigger" collapses to the
// same skeleton as the allowed "niger", so the allow list silently ate the
// slur it was meant to work around. Checking position instead means an allowed
// word only excuses the letters it actually covers -- "peacock" excuses the
// "cock" inside it and nothing else, so "peacockfuck" is still caught.
function coveredByAllow(text, start, end, allowNorms) {
  for (const a of allowNorms) {
    let i = text.indexOf(a);
    while (i !== -1) {
      if (i <= start && (i + a.length) >= end) return true;
      i = text.indexOf(a, i + 1);
    }
  }
  return false;
}

// Returns the offending term, or null if the name is acceptable.
// Returning the term (rather than a boolean) lets the caller log WHY without
// having to guess, and lets the admin see which entry fired.
function check(name, config) {
  const cfg = sanitizeConfig(config);
  if (!cfg.enabled) return null;

  const n = normalize(name);
  if (!n) return null;

  // Whole-name matches first. Checked against the raw normalized name --
  // someone literally named "cock" is caught even though "cockpit" is fine.
  for (const term of cfg.blockExact) {
    if (normalize(term) && n === normalize(term)) return term;
  }

  const allowNorms = cfg.allow.map(normalize).filter(Boolean);

  // Every occurrence is checked, not just the first -- otherwise a name could
  // hide a real hit behind an innocent one.
  for (const term of cfg.blockContains) {
    const t = normalize(term);
    if (!t) continue;
    let i = n.indexOf(t);
    while (i !== -1) {
      if (!coveredByAllow(n, i, i + t.length, allowNorms)) return term;
      i = n.indexOf(t, i + 1);
    }
  }

  return null;
}

module.exports = { check, normalize, defaultConfig, sanitizeConfig, DEFAULT_CONFIG };
