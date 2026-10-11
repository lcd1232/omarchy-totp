import { test } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

// Model.js is a QML JS library (".pragma library"); load it as a plain script.
const src = readFileSync(new URL("../Model.js", import.meta.url), "utf8").replace(/^\.pragma library\s*$/m, "")
const names = ["parseList", "formatCode", "entryKey", "codeState", "refreshAt", "matchScore",
  "rankEntries", "errorHint", "skippedHint", "statusHint"]
const M = new Function(`${src}\nreturn { ${names.join(", ")} }`)()

const e = (issuer, extra = {}) => ({ id: issuer.toLowerCase(), issuer, account: "", ...extra })
const ids = rows => rows.map(r => r.entry.id)

test("Ente-pinned entries come first", () => {
  const rows = M.rankEntries([e("Alpha"), e("Beta", { pinned: true }), e("Gamma")], "", {}, "alpha")
  assert.deepEqual(ids(rows), ["beta", "alpha", "gamma"])
  assert.equal(rows[0].pinned, true)
  assert.equal(rows[1].pinned, false)
})

test("match quality beats pinning", () => {
  const rows = M.rankEntries([e("GitHub"), e("Legit", { pinned: true })], "git", {}, "alpha")
  assert.deepEqual(ids(rows), ["github", "legit"])
})

test("recent sort uses last-used times", () => {
  const used = { "id:alpha": 10, "id:gamma": 20 }
  assert.deepEqual(ids(M.rankEntries([e("Alpha"), e("Beta"), e("Gamma")], "", used, "recent")),
    ["gamma", "alpha", "beta"])
})

test("ente sort uses position, then helper order", () => {
  const list = [e("A", { position: 2 }), e("B", { position: 0 }), e("C", { position: 2 }), e("D")]
  assert.deepEqual(ids(M.rankEntries(list, "", {}, "ente")), ["b", "d", "a", "c"])
})

test("unknown sort mode falls back to alphabetical", () => {
  assert.deepEqual(ids(M.rankEntries([e("Zed"), e("Abe")], "", {}, "vault")), ["abe", "zed"])
})

test("error hints name Ente Auth", () => {
  assert.equal(M.errorHint({ code: "DB_MISSING" }),
    "Ente Auth data not found — open Ente Auth and sign in once (DB_MISSING)")
  assert.equal(M.errorHint({ code: "NOT_SIGNED_IN" }), "Not signed in to Ente Auth (NOT_SIGNED_IN)")
  assert.equal(M.errorHint({ code: "DB_BUSY" }), "Ente Auth is busy, retry (DB_BUSY)")
  assert.equal(M.errorHint({ code: "OTHER", message: "boom" }), "boom")
  for (const code of ["DEPS_MISSING", "KEYRING_LOCKED", "UNSUPPORTED_SCHEMA", "HELPER_TIMEOUT",
    "OUTPUT_TOO_LARGE", "DECRYPT_FAILED"])
    assert.ok(M.errorHint({ code }).endsWith(`(${code})`), code)
  assert.doesNotMatch(JSON.stringify(names.map(n => String(M[n]))), /Proton/)
})

test("skipped hint", () => {
  assert.equal(M.skippedHint(0), "")
  assert.equal(M.skippedHint(1), "1 entry could not be read")
  assert.equal(M.skippedHint(3), "3 entries could not be read")
})

test("status hint", () => {
  const base = { refreshing: false, ok: true, error: null, total: 2, shown: 2, query: "", skipped: 0 }
  assert.equal(M.statusHint(base), "")
  assert.equal(M.statusHint({ ...base, refreshing: true, total: 0, shown: 0 }), "Loading…")
  assert.equal(M.statusHint({ ...base, ok: false, error: { code: "DB_BUSY" } }), "Ente Auth is busy, retry (DB_BUSY)")
  assert.equal(M.statusHint({ ...base, total: 0, shown: 0 }), "No codes — add them in Ente Auth")
  assert.equal(M.statusHint({ ...base, shown: 0, query: "zz" }), "No matches")
  assert.equal(M.statusHint({ ...base, skipped: 2 }), "2 entries could not be read")
  assert.equal(M.statusHint({ ...base, total: 0, shown: 0, skipped: 1 }), "1 entry could not be read")
})

test("codeState and refreshAt are unchanged from the reference", () => {
  const entry = { period: 30, counter: 1, codes: ["111111", "222222", "333333"] }
  assert.deepEqual(M.codeState(entry, 65), { code: "222222", next: "333333", remaining: 25, period: 30, stale: false })
  assert.equal(M.codeState(entry, 200).stale, true)
  assert.equal(M.refreshAt([entry]), 90)
  assert.equal(M.formatCode("123456"), "123 456")
})
