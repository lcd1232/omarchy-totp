import { test } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

// Model.js is a QML JS library (".pragma library"); load it as a plain script.
const src = readFileSync(new URL("../Model.js", import.meta.url), "utf8").replace(/^\.pragma library\s*$/m, "")
const names = ["parseList", "formatCode", "entryKey", "codeState", "refreshAt", "matchScore",
  "rankEntries", "errorHint", "skippedHint", "statusHint", "installCommand", "canCopyCommand"]
const M = new Function(`${src}\nreturn { ${names.join(", ")} }`)()

const e = (issuer, extra = {}) => ({ id: issuer.toLowerCase(), issuer, account: "", ...extra })
const ids = rows => rows.map(r => r.entry.id)

test("Ente-pinned entries come first", () => {
  const rows = M.rankEntries([e("Alpha"), e("Beta", { pinned: true }), e("Gamma")], "")
  assert.deepEqual(ids(rows), ["beta", "alpha", "gamma"])
  assert.equal(rows[0].pinned, true)
  assert.equal(rows[1].pinned, false)
})

test("match quality beats pinning", () => {
  const rows = M.rankEntries([e("GitHub"), e("Legit", { pinned: true })], "git")
  assert.deepEqual(ids(rows), ["github", "legit"])
})

test("most recently used in Ente first, then A-Z", () => {
  const list = [e("Alpha"), e("Beta", { lastUsedAt: 10 }), e("Gamma", { lastUsedAt: 20 }), e("Delta")]
  assert.deepEqual(ids(M.rankEntries(list, "")), ["gamma", "beta", "alpha", "delta"])
})

test("pinned beats recently used; recency orders within pinned", () => {
  const list = [e("Alpha", { lastUsedAt: 99 }), e("Beta", { pinned: true, lastUsedAt: 1 }),
    e("Gamma", { pinned: true, lastUsedAt: 5 })]
  assert.deepEqual(ids(M.rankEntries(list, "")), ["gamma", "beta", "alpha"])
})

test("recency applies within the same match quality", () => {
  const list = [e("GitHub"), e("GitLab", { lastUsedAt: 3 })]
  assert.deepEqual(ids(M.rankEntries(list, "git")), ["gitlab", "github"])
})

test("same name sorts by account", () => {
  const list = [{ id: "2", issuer: "Google", account: "zed@x" }, { id: "1", issuer: "Google", account: "abe@x" }]
  assert.deepEqual(ids(M.rankEntries(list, "")), ["1", "2"])
})

test("error hints are plain sentences without codes", () => {
  assert.equal(M.errorHint({ code: "APP_MISSING" }), "Ente Auth is not installed")
  assert.equal(M.errorHint({ code: "DB_MISSING" }), "Ente Auth has no data yet — open it and sign in once")
  assert.equal(M.errorHint({ code: "NOT_SIGNED_IN" }), "Not signed in to Ente Auth — open it and sign in")
  assert.equal(M.errorHint({ code: "DB_BUSY" }), "Ente Auth is busy — try again")
  assert.equal(M.errorHint({ code: "OTHER", message: "boom" }), "boom")
  for (const code of ["DEPS_MISSING", "KEYRING_LOCKED", "UNSUPPORTED_SCHEMA", "HELPER_TIMEOUT",
    "OUTPUT_TOO_LARGE", "DECRYPT_FAILED"]) {
    const hint = M.errorHint({ code, message: "raw" })
    assert.ok(hint.length > 0 && hint !== "raw" && !hint.includes(code), code)
  }
  assert.doesNotMatch(JSON.stringify(names.map(n => String(M[n]))), /Proton/)
})

test("install command is only shown when it is an omarchy pkg add command", () => {
  assert.equal(M.installCommand({ install: "omarchy pkg aur add ente-auth-bin" }), "omarchy pkg aur add ente-auth-bin")
  assert.equal(M.installCommand({ install: "omarchy pkg add libsodium wl-clipboard" }), "omarchy pkg add libsodium wl-clipboard")
  for (const bad of [undefined, "", "rm -rf ~", "omarchy pkg add x; rm -rf ~", "omarchy pkg add $(id)", "omarchy pkg add"])
    assert.equal(M.installCommand({ install: bad }), "", String(bad))
  assert.equal(M.installCommand(null), "")
})

test("copy button needs wl-clipboard", () => {
  assert.equal(M.canCopyCommand("omarchy pkg aur add ente-auth-bin"), true)
  assert.equal(M.canCopyCommand("omarchy pkg add libsodium wl-clipboard"), false)
  assert.equal(M.canCopyCommand(""), false)
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
  assert.equal(M.statusHint({ ...base, ok: false, error: { code: "DB_BUSY" } }), "Ente Auth is busy — try again")
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
