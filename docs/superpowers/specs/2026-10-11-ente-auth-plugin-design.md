# Omarchy Ente Auth plugin — design

Date: 2026-10-11
Status: approved

## Goal

An Omarchy shell (Quickshell) bar plugin that shows [Ente Auth](https://ente.io/auth)
TOTP codes in a launcher-style panel: open the panel, type a few letters, press
Enter, the current code is on the clipboard. No network, no Ente Auth window.

It looks and behaves like
[omarchy-proton-authenticator](https://github.com/navjottomer/omarchy-proton-authenticator)
(MIT), but codes come from Ente Auth's local data.

Success: with Ente Auth desktop installed and signed in on this machine, the
bar icon opens the panel, Enter copies the right code, and Ente Auth does not
need to be running.

## Decisions

- **Source of codes:** Ente Auth desktop's local encrypted DB plus its key in
  the Secret Service keyring, decrypted in memory. No `ente` CLI, no fallback
  to it, no network.
- **Plugin ID:** `lcd1232.ente-auth`. New repo (this one); QML ported from the
  reference plugin with credit in README and LICENSE.
- **Pins:** only Ente's own `pinned` flag. The plugin has no pin action and
  stores no pins.
- **Order:** Ente-pinned first, then most recently used per Ente's
  `codeDisplay.lastUsedAt` (newest first), then A–Z. No sort setting. The
  plugin stores no usage state; copying from the panel does not reorder
  (decided 2026-10-11, after review).
- **No "Open Ente Auth" button.** Empty/error states say what to do in text.
- **Out of scope:** HOTP and Steam entries (skipped), Ente notes, tags and
  icons, writing anything back to Ente.

## Verified facts (spike, 2026-10-11, Ente Auth 4.4.24)

- DB: `~/.local/share/io.ente.auth/.ente.authenticator.db`, table `entities`
  (`_generatedID`, `id`, `encryptedData`, `header`, `createdAt`, `updatedAt`,
  `shouldSync`). `encryptedData` and `header` are standard base64.
- Keyring item: attribute `account=io.ente.auth.secureStorage`; its secret is a
  JSON object of flutter_secure_storage values. `auth_secret_key` is the
  base64 32-byte key for the entities.
- Each row is a single libsodium `crypto_secretstream_xchacha20poly1305`
  message (`header` = stream header). Tags seen: both `TAG_MESSAGE` (0) and
  `TAG_FINAL` (3); both must be accepted.
- Plaintext is a JSON-encoded string holding an `otpauth://totp/...` URI.
  Query params: `secret`, `issuer`, `algorithm`, `digits`, `period`,
  `codeDisplay`.
- `codeDisplay` is JSON: `pinned`, `trashed`, `lastUsedAt`, `tapCount`,
  `tags`, `note`, `position`, `iconSrc`, `iconID`. Trashed entries exist in
  real data and must be hidden.
- This is the same entity format the official CLI decrypts
  (`cli/pkg/mapper/authenticator.go`), i.e. Ente's E2EE sync format, not a
  private cache format.
- Offline mode (no account) uses `offline_auth_secret_key` and a separate
  offline DB (`OfflineAuthenticatorDB` in the app source); same row format.

## Layout

```
manifest.json            plugin manifest (id lcd1232.ente-auth)
Panel.qml                ported; pin action removed, Proton button removed
Service.qml              ported; runs bin/enteauth-list
Model.js                 ported; sort = Ente-pinned, Ente lastUsedAt, A–Z
EnteAuthIcon.qml         ported bar icon
assets/icon.svg
bin/enteauth-list        wrapper: exec /usr/bin/python3 -I enteauth_list.py "$@"
bin/enteauth_list.py     new: reads DB + keyring, emits codes as JSON
bin/enteauth-clipcheck   ported unchanged apart from names
tests/                   unittest suite for the helper
.github/workflows/ci.yml tests + shellcheck + manifest check
README.md, LICENSE       MIT, credits the reference plugin
```

## Helper: `bin/enteauth_list.py`

Stdlib only plus libsodium via `ctypes`.

1. **Key.** `secret-tool lookup account io.ente.auth.secureStorage`, parse
   JSON. Use `auth_secret_key` with the online DB; if absent and
   `offline_auth_secret_key` exists, use it with the offline DB.
2. **DB.** Open read-only (`file:...?mode=ro`, `uri=True`). On
   `database is locked`, retry once after 200 ms.
3. **Decrypt.** `crypto_secretstream_xchacha20poly1305_init_pull` +
   `_pull` per row. Accept tags 0 and 3. JSON-decode to the URI string.
   A row that fails is counted, not fatal.
4. **Parse.** `otpauth://totp/<label>?...`: account and issuer from the
   label (`Issuer:account`) or the `issuer` param; defaults digits 6,
   period 30, SHA1. Drop `trashed`. Skip non-`totp` types.
5. **TOTP.** RFC 6238 with stdlib `hmac`/`hashlib` (SHA1, SHA256, SHA512);
   compute the next 10 codes per entry.
6. **Output.** Same JSON contract as the reference helper
   (`entries`, `error`), each entry with `id`, `issuer`, `account`,
   `pinned`, `position`, `lastUsedAt` (int, 0 if missing/invalid), `period`, codes. `id` = Ente entity `id`, or
   `local-<_generatedID>` if unsynced. Refuse to emit if any entry carries
   a `secret` field. Add `skipped` (count of unreadable rows).

Flags kept from the reference: `--check` (counts only, no codes), `--demo`
(fake accounts), `--window N`, `--version`; overall alarm timeout; fail closed
with a JSON error.

Error codes: `DB_MISSING`, `KEYRING_LOCKED`, `NOT_SIGNED_IN`, `DB_BUSY`,
`DECRYPT_FAILED`, `DEPS_MISSING`. Messages never contain decrypted data; for
unexpected exceptions only the exception type is reported.

## Panel behaviour

Same as the reference: search focused on open, Enter copies the top match,
Shift+Enter copies the next code, keyboard navigation, Tab to next panel,
Esc closes, click to copy, right-click bar icon reloads. Removed: Ctrl+P /
right-click pinning and the "Add in …" button.

Ordering (after match quality while searching): Ente-pinned entries first,
then Ente's `lastUsedAt` (newest first), then A–Z.

Settings (`omarchy bar set lcd1232.ente-auth <key> <value>`):
`closeOnCopy`, `notifyOnCopy`, `clipboardClearSec`, `demoMode` — same
meanings as the reference.

Refresh: helper runs on open and again when codes run low (~5 min); codes for
"now" are chosen from the panel's clock.

| Condition | Panel text |
|---|---|
| `DB_MISSING` | Ente Auth data not found — open Ente Auth and sign in once |
| `KEYRING_LOCKED` | Keyring is locked |
| `NOT_SIGNED_IN` | Not signed in to Ente Auth |
| `DB_BUSY` | Ente Auth is busy, retry |
| `DEPS_MISSING` | Missing dependency: … |
| `skipped > 0` | footer: N entries could not be read |
| no entries | No codes — add them in Ente Auth |

## Security

- Secrets exist only inside the short-lived helper; the shell sees labels and
  codes and drops them when the panel closes.
- DB opened read-only; nothing decrypted is written to disk.
- Codes go to `wl-copy --sensitive` on stdin; clearing is checked by
  `enteauth-clipcheck` without reading the clipboard into the shell.
- The plugin stores no state files.

## Dependencies

`ente-auth-bin`, `libsodium`, `libsecret`, `wl-clipboard`, `libnotify`,
Omarchy with the Quickshell shell. No Python packages.

## Testing

`python3 -m unittest` in `tests/`, no network or real keyring:

- TOTP against RFC 6238 vectors (SHA1/256/512).
- `otpauth` parsing: label vs param issuer, defaults, percent-encoding.
- Trashed filtered, pinned and position passed through, HOTP skipped.
- End to end: encrypt fixture URIs with libsodium secretstream into a temp
  SQLite DB, run the helper with an injected key, check JSON and that no
  `secret` appears; one corrupted row gives `skipped: 1`.
- Each error code path.

Development is test-driven: every helper behaviour above gets a failing test
first, then the minimal code to pass it. libsodium is loaded via
`ctypes.util.find_library("sodium")` (soname differs between distros).

### CI

GitHub Actions, `.github/workflows/ci.yml`, on push and pull request:

- Job runs in an `archlinux:latest` container (matches Omarchy):
  `pacman -Syu --noconfirm python libsodium shellcheck`.
- `python -m unittest discover -s tests -v`
- `shellcheck bin/enteauth-list bin/enteauth-clipcheck`.
- `python -m json.tool manifest.json` (manifest is valid JSON).

QML is not linted in CI (Quickshell/Omarchy types are not available there).

Manual: `bin/enteauth-list --check` on the real DB; install with
`omarchy plugin add <path> --enable`; check search, Enter, Shift+Enter, Ente
pins on top, clipboard clearing, error states (lock keyring).
