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

// Stable key for recent-use. The Ente entity id when there is one.
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

// Filter by query, then order: match quality, Ente-pinned, then sortMode
// ("recent": last copied here; "ente": Ente's own position; else A-Z).
function rankEntries(entries, query, used, sortMode) {
  var q = String(query || "").trim().toLowerCase()
  var rows = []
  var list = entries || []
  for (var i = 0; i < list.length; i++) {
    var e = list[i]
    var score = matchScore(e, q)
    if (score < 0) continue
    rows.push({ e: e, score: score, pinned: e.pinned === true,
      used: Number(used && used[entryKey(e)]) || 0, position: Number(e.position) || 0, index: i })
  }
  rows.sort(function(a, b) {
    if (a.score !== b.score) return a.score - b.score
    if (a.pinned !== b.pinned) return a.pinned ? -1 : 1
    if (sortMode === "recent" && a.used !== b.used) return b.used - a.used
    if (sortMode === "ente") return a.position !== b.position ? a.position - b.position : a.index - b.index
    var ai = String(a.e.issuer || "").toLowerCase(), bi = String(b.e.issuer || "").toLowerCase()
    if (ai !== bi) return ai < bi ? -1 : 1
    var aa = String(a.e.account || "").toLowerCase(), ba = String(b.e.account || "").toLowerCase()
    return aa < ba ? -1 : (aa > ba ? 1 : a.index - b.index)
  })
  var out = []
  for (var k = 0; k < rows.length; k++) out.push({ entry: rows[k].e, pinned: rows[k].pinned })
  return out
}

// Human-readable status for helper error codes.
function errorHint(error) {
  if (!error) return ""
  var code = String(error.code || "")
  var hints = {
    DEPS_MISSING: "Missing dependency (libsodium, libsecret)",
    DB_MISSING: "Ente Auth data not found — open Ente Auth and sign in once",
    NOT_SIGNED_IN: "Not signed in to Ente Auth",
    KEYRING_LOCKED: "Keyring is locked — unlock it and retry",
    DB_BUSY: "Ente Auth is busy, retry",
    UNSUPPORTED_SCHEMA: "Unsupported Ente Auth version",
    HELPER_TIMEOUT: "Timed out reading the keyring — unlock it and retry",
    OUTPUT_TOO_LARGE: "Too many accounts to display",
    DECRYPT_FAILED: "Could not decrypt Ente Auth data"
  }
  var hint = hints[code] || ""
  var msg = String(error.message || code || "Error")
  return hint ? hint + " (" + code + ")" : msg
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
