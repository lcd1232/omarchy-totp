.pragma library

function parseList(raw) {
  try {
    var data = JSON.parse(String(raw || ""))
    if (!data || typeof data !== "object")
      return { ok: false, entries: [], error: { code: "DECRYPT_FAILED", message: "Invalid JSON" } }
    if (!Array.isArray(data.entries)) data.entries = []
    return data
  } catch (e) {
    return { ok: false, entries: [], error: { code: "DECRYPT_FAILED", message: String(e) } }
  }
}

function formatCode(code) {
  var s = String(code || "").replace(/\s+/g, "")
  if (s.length === 6) return s.slice(0, 3) + " " + s.slice(3)
  if (s.length === 8) return s.slice(0, 4) + " " + s.slice(4)
  return s
}

// Stable key for a row (copied-row highlight). The Ente entity id when there is one.
function entryKey(entry) {
  if (!entry) return ""
  if (entry.id) return "id:" + String(entry.id)
  return "label:" + String(entry.issuer || "") + "|" + String(entry.account || "")
}

// Current code, next code and countdown for `nowSec`, picked from the window
// of codes the helper sent. `stale` means the window has run out.
function codeState(entry, nowSec) {
  var period = Number(entry && entry.period) || 30
  var codes = (entry && entry.codes) || []
  var idx = Math.floor(nowSec / period) - Number(entry && entry.counter || 0)
  var ok = idx >= 0 && idx < codes.length
  return {
    code: ok ? codes[idx] : "",
    next: ok && idx + 1 < codes.length ? codes[idx + 1] : "",
    remaining: period - (Math.floor(nowSec) % period),
    period: period,
    stale: !ok
  }
}

// When to fetch a new window: once any entry is down to its last code.
function refreshAt(entries) {
  var at = Infinity
  for (var i = 0; i < (entries || []).length; i++) {
    var e = entries[i]
    var period = Number(e.period) || 30
    var n = (e.codes || []).length
    if (n === 0) continue
    at = Math.min(at, (Number(e.counter) + n - 1) * period)
  }
  return at
}

// Lower is better; -1 means no match.
function matchScore(entry, q) {
  if (!q) return 0
  var issuer = String(entry.issuer || "").toLowerCase()
  var account = String(entry.account || "").toLowerCase()
  if (issuer.indexOf(q) === 0) return 0
  if ((" " + issuer).indexOf(" " + q) >= 0) return 1
  if (issuer.indexOf(q) >= 0) return 2
  if (account.indexOf(q) >= 0) return 3
  // Letters in order, e.g. "gh" for GitHub.
  var hay = issuer + " " + account, j = 0
  for (var i = 0; i < hay.length && j < q.length; i++) if (hay[i] === q[j]) j++
  return j === q.length ? 4 : -1
}

// Filter by query, then order: match quality, Ente-pinned, most recently
// used in Ente (codeDisplay.lastUsedAt, newest first), then A-Z.
function rankEntries(entries, query) {
  var q = String(query || "").trim().toLowerCase()
  var rows = []
  var list = entries || []
  for (var i = 0; i < list.length; i++) {
    var e = list[i]
    var score = matchScore(e, q)
    if (score < 0) continue
    rows.push({ e: e, score: score, pinned: e.pinned === true, used: Number(e.lastUsedAt) || 0, index: i })
  }
  rows.sort(function(a, b) {
    if (a.score !== b.score) return a.score - b.score
    if (a.pinned !== b.pinned) return a.pinned ? -1 : 1
    if (a.used !== b.used) return b.used - a.used
    var ai = String(a.e.issuer || "").toLowerCase(), bi = String(b.e.issuer || "").toLowerCase()
    if (ai !== bi) return ai < bi ? -1 : 1
    var aa = String(a.e.account || "").toLowerCase(), ba = String(b.e.account || "").toLowerCase()
    return aa < ba ? -1 : (aa > ba ? 1 : a.index - b.index)
  })
  var out = []
  for (var k = 0; k < rows.length; k++) out.push({ entry: rows[k].e, pinned: rows[k].pinned })
  return out
}

// What the panel says for each helper error code: a short heading saying
// what is wrong (errorHint) and a line saying what to do (errorDetail). The
// code itself is not shown; an unknown code falls back to the helper's message.
function errorHint(error) {
  if (!error) return ""
  var code = String(error.code || "")
  var hints = {
    APP_MISSING: "Ente Auth isn't installed",
    DEPS_MISSING: "Some packages this plugin needs aren't installed",
    DB_MISSING: "Ente Auth isn't set up yet",
    NOT_SIGNED_IN: "Not signed in to Ente Auth",
    KEYRING_LOCKED: "Your keyring is locked",
    DB_BUSY: "Ente Auth is busy",
    UNSUPPORTED_SCHEMA: "This Ente Auth version isn't supported",
    HELPER_TIMEOUT: "Timed out reading the keyring",
    OUTPUT_TOO_LARGE: "Too many accounts to show",
    DECRYPT_FAILED: "Couldn't decrypt Ente Auth data"
  }
  return hints[code] || String(error.message || code || "Error")
}

function errorDetail(error) {
  if (!error) return ""
  var code = String(error.code || "")
  if (code === "APP_MISSING" || code === "DEPS_MISSING") {
    if (!installCommand(error)) return ""
    return (code === "APP_MISSING" ? "Install it" : "Install them") + " by running this command in a terminal:"
  }
  var signIn = "Open Ente Auth and sign in, or tap \"Use without backups\". Your codes will appear here."
  var details = {
    DB_MISSING: signIn,
    NOT_SIGNED_IN: signIn,
    KEYRING_LOCKED: "Unlock it, then open this panel again.",
    DB_BUSY: "It's saving its data. Try again in a moment.",
    UNSUPPORTED_SCHEMA: "Check for an update to this plugin.",
    HELPER_TIMEOUT: "Unlock your keyring, then open this panel again.",
    DECRYPT_FAILED: "Open Ente Auth once so it can sync, then try again."
  }
  return details[code] || ""
}

// The install command for an error, if any. Only plain `omarchy pkg [aur] add`
// commands are shown, since the user is expected to paste it into a terminal.
function installCommand(error) {
  var cmd = String((error && error.install) || "")
  return /^omarchy pkg (aur )?add( [a-z0-9][a-z0-9@._+-]*)+$/.test(cmd) ? cmd : ""
}

// Copying uses wl-copy, so it can't work while wl-clipboard is what's missing.
function canCopyCommand(cmd) {
  return cmd.length > 0 && !/(^| )wl-clipboard( |$)/.test(cmd)
}

function skippedHint(n) {
  n = Number(n) || 0
  if (n <= 0) return ""
  return n + (n === 1 ? " entry" : " entries") + " could not be read"
}

// The line above the list: loading, error, empty or partial-read notice.
function statusHint(s) {
  if (s.refreshing && s.total === 0) return "Loading…"
  if (!s.ok && s.error) return errorHint(s.error)
  if (s.shown === 0 && s.query) return "No matches"
  if (s.skipped > 0) return skippedHint(s.skipped)
  if (s.shown === 0) return "No codes — add them in Ente Auth"
  return ""
}

// Relative luminance (WCAG, as Flutter's computeLuminance) of 0..1 channels.
function _luminance(r, g, b) {
  function lin(c) { return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4) }
  return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b)
}

function isDarkColor(r, g, b) {
  return _luminance(r, g, b) < 0.5
}

// How to colour an account icon, like Ente Auth: "#RRGGBB" for the brand
// colour, "" to keep a multi-colour icon's own colours, or "foreground" when
// the brand colour is a grey that would vanish on this theme.
function iconTint(hex, darkTheme) {
  var h = String(hex || "")
  if (!/^[0-9A-Fa-f]{6}$/.test(h)) return ""
  var r = parseInt(h.slice(0, 2), 16), g = parseInt(h.slice(2, 4), 16), b = parseInt(h.slice(4, 6), 16)
  var grey = Math.abs(r - g) <= 3 && Math.abs(g - b) <= 3 && Math.abs(b - r) <= 3
  var lum = _luminance(r / 255, g / 255, b / 255)
  if (grey && (darkTheme ? lum < 0.05 : lum > 0.70)) return "foreground"
  return "#" + h.toUpperCase()
}

// Letter shown in place of an icon when Ente Auth has none for the account.
function avatarLetter(entry) {
  var name = String((entry && entry.issuer) || "").trim() || String((entry && entry.account) || "").trim()
  return name ? name.charAt(0).toUpperCase() : ""
}
