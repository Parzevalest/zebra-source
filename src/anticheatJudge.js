// ── Server-side anti-cheat judgment ─────────────────────────────────────────
//
// The browser DETECTS (it's the only place that can watch typing) and this
// module JUDGES. The client sends raw observations -- booleans and numbers
// about what happened -- and the server alone decides "bot / suspect / clean"
// and what the ban confidence is.
//
// Why this exists: the /anticheat route used to trust `confidence` straight
// from the request body, gated on `if (confidence >= 99)`. A cheater with dev
// tools open just sent `confidence: 0` and was never banned. The client's
// verdict is now ignored entirely -- only the raw signals are read, and the
// scoring below (which lives on the server and never ships to the browser) is
// what decides.
//
// The weights mirror the client's original scoring so behaviour is unchanged
// for honest players; the difference is purely that a cheater can no longer
// edit the verdict, because the verdict is no longer theirs to send.

// Score contributions. Kept in one table so the curve is legible and tunable
// without hunting through branches.
const WEIGHTS = {
  canvasPresent: 35,
  webglPresent: 30,
  audioPresent: 20,
  hardwareBaseline: 15,
  sessionBotMajority: 20,
};

// Raw signals that CANNOT be produced by a normal human browser. Any one of
// these forces the auto-ban confidence directly -- they're the fingerprints of
// programmatic input (autotyper / userscript / automation tool), not of a
// privacy extension or dev tools. Deliberately excludes the softer signals
// (perfNowMocked, dispatchEventOverridden, programmaticFocus) that legitimately
// fire on Brave/Firefox-RFP, ad blockers, and keyboard navigation.
function certainInjection(s) {
  return !!(
    s.syntheticKeyDetected ||
    s.nativeSetterTampered ||
    s.execCommandDetected ||
    s.webdriverFlag ||
    s.automationArtifacts
  );
}

// DOM evidence strong enough to convict at a much lower score than behaviour
// alone would need.
function domHardSignal(s) {
  return !!(
    s.syntheticKeyDetected ||
    s.nativeSetterTampered ||
    s.execCommandDetected ||
    s.descriptorRepatched ||
    (s.keypressValueMismatches || 0) >= 5 ||
    (s.valueJumpCount || 0) >= 3 ||
    s.webdriverFlag ||
    s.automationArtifacts
  );
}

// Physically impossible or near-impossible typing. Server-computed from the
// timing summary the client reports -- and note the server ALSO has the actual
// race WPM independently (races are recorded server-side), so a client that
// lies in `timings` still can't fake a human race history.
function timingHardSignal(t) {
  if (!t || t.insufficient) return false;
  return !!(
    t.physicallyImpossible ||                    // >=250 WPM
    (t.extremelyFast && t.tooUniform) ||         // 180-249 WPM + robotic uniformity
    (t.badTriplets && t.badHold)                 // near-instant triplets + short hold
  );
}

// The confidence curve, moved verbatim from the client's _confidence().
function confidenceForScore(score) {
  if (score >= 100) return 99;
  if (score >= 80) return 97;
  if (score >= 60) return 95;
  if (score >= 50) return 90;
  if (score >= 40) return 80;
  if (score >= 30) return 60;
  if (score >= 20) return 40;
  return Math.round(score * 1.5);
}

// Re-scores a report from its raw signals. Returns the SERVER's verdict; the
// client's claimed score/confidence are not read.
//
// `report.signals` is the flat object of raw booleans/counts the browser
// observed. `report.timings` is its timing summary. Missing fields are treated
// as "not observed" (falsy), so an attacker deleting fields only ever makes
// themselves look cleaner -- never someone else look guilty.
function judge(report) {
  const s = (report && report.signals) || {};
  const t = (report && report.timings) || {};
  const session = (report && report.session) || {};

  // Two separate tallies.
  //
  // `baseline` is the hardware-fingerprint score: canvas/webgl/audio present +
  // the flat 15. On a perfectly normal browser this sums to 100. It means
  // "this is a real browser," which is the OPPOSITE of suspicious -- so it must
  // never, on its own, push someone over a bot threshold. It exists only so
  // that a headless/spoofed browser (which lacks these) scores LOWER, not so a
  // real one scores high.
  //
  // `evidence` is the actual bot-behaviour score: timing anomalies, session
  // bot-rate, DOM tampering. This is what the thresholds are measured against.
  //
  // Conflating the two is how a clean browser -- or a player running an
  // autoreload userscript that trips nothing but has a normal fingerprint --
  // could read as isBot at score 100. Keeping them apart fixes that.
  let baseline = 0;
  let evidence = 0;
  const reasons = [];

  if (s.canvasPresent) baseline += WEIGHTS.canvasPresent;
  if (s.webglPresent) baseline += WEIGHTS.webglPresent;
  if (s.audioPresent) baseline += WEIGHTS.audioPresent;
  baseline += WEIGHTS.hardwareBaseline;

  // Session-level: a majority of a player's recent races flagged bot-like.
  const races = session.races || 0;
  const botRaces = session.botRaces || 0;
  const sessionBotRate = races > 2 ? botRaces / races : 0;
  if (sessionBotRate > 0.5) {
    evidence += WEIGHTS.sessionBotMajority;
    reasons.push(`session bot rate ${Math.round(sessionBotRate * 100)}% over ${races} races`);
  }

  // Timing-derived evidence. The client added these same points; without them
  // a timing-only bot (the 300 WPM autotyper you actually saw) would clear the
  // hard-signal gate but never reach the score threshold to be convicted.
  if (!t.insufficient) {
    if (t.physicallyImpossible) { evidence += 80; reasons.push(`impossible speed ${t.impliedWPM || "?"} WPM`); }
    else if (t.extremelyFast) { evidence += 30; reasons.push(`extremely fast ${t.impliedWPM || "?"} WPM`); }
    if (t.tooUniform) { evidence += 20; reasons.push("uniform timing"); }
    if (t.tooRepetitive) { evidence += 15; reasons.push("repetitive interval"); }
    if (t.badHold) { evidence += 25; reasons.push("abnormal key hold"); }
    if (t.badTriplets) { evidence += 25; reasons.push("near-instant triplets"); }
    if (t.flatSpeed) { evidence += 15; reasons.push("flat speed"); }
  }

  // The score the thresholds are measured against is EVIDENCE, not baseline.
  // Baseline is reported for the admin log but never convicts.
  const score = evidence;

  const hard = domHardSignal(s) || timingHardSignal(t);
  if (domHardSignal(s)) reasons.push("hard DOM signal (synthetic input / tampering)");
  if (timingHardSignal(t)) reasons.push("hard timing signal (impossible speed)");

  const injection = certainInjection(s);
  if (injection) reasons.push("certain injection signal");

  // A confirmed-injection signal has no innocent explanation, so it pins
  // confidence at the ban threshold regardless of the additive score.
  const confidence = injection ? 99 : confidenceForScore(score);

  // Hard signal convicts at 40; pure behavioural evidence needs 90.
  const isBot = hard ? score >= 40 : score >= 90;
  const isSuspect = !isBot && score >= 35;

  // Auto-ban requires ACTUAL bot evidence -- an injection signal, or a bot
  // verdict backed by a hard signal. Never the baseline fingerprint alone, and
  // never a soft signal like an overridden setInterval (which autoreload
  // userscripts and privacy browsers trip routinely). This is what makes an
  // autoreload user safe: nothing they do produces a hard signal or injection.
  const shouldAutoBan = injection || (isBot && hard) || (confidence >= 99 && hard);

  return {
    score,
    baseline,
    confidence,
    isBot,
    isSuspect,
    hard,
    reasons,
    shouldAutoBan,
  };
}

module.exports = { judge, confidenceForScore, WEIGHTS };
