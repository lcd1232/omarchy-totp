# Ente Auth Omarchy Plugin Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An Omarchy bar plugin (`lcd1232.ente-auth`) that lists Ente Auth TOTP codes in a launcher-style panel, reading the Ente Auth desktop app's local encrypted DB and keyring key, with no network.

**Architecture:** A stdlib-only Python helper (`bin/enteauth_list.py`) reads the SQLite DB read-only, gets the key from the Secret Service keyring via `secret-tool`, decrypts each row with libsodium secretstream (through `ctypes`), parses the `otpauth://` URI and prints labels plus a window of upcoming codes as one JSON line. The QML panel is ported from the MIT-licensed reference plugin and consumes that JSON unchanged in shape.

**Tech Stack:** Python 3 stdlib + libsodium (ctypes), Quickshell QML (Omarchy shell), plain JS (`Model.js`) tested with `node --test`, POSIX sh, GitHub Actions in an `archlinux:latest` container.

**Spec:** `docs/superpowers/specs/2026-10-11-ente-auth-plugin-design.md`

**Reference plugin:** https://github.com/navjottomer/omarchy-proton-authenticator at commit `90ad4d19b4c115d0259e0a072c186972d8d41c47` (MIT, © 2026 mapski). Tasks that port files say: "copy `<file>` from the reference". Get it with:

```bash
git clone https://github.com/navjottomer/omarchy-proton-authenticator /tmp/ref-proton
git -C /tmp/ref-proton checkout 90ad4d19b4c115d0259e0a072c186972d8d41c47
```

## Global Constraints

- Plugin ID `lcd1232.ente-auth`; display name "Ente Auth"; license MIT, credit the reference plugin.
- Codes come only from Ente Auth desktop's local DB + keyring. No `ente` CLI, no CLI fallback, no network.
- Online DB: `~/.local/share/io.ente.auth/.ente.authenticator.db`; offline DB: `~/.local/share/io.ente.auth/.ente.offline_authenticator.db`; table `entities`.
- Keyring: `secret-tool lookup account io.ente.auth.secureStorage` → JSON object; keys `auth_secret_key` (online) and `offline_auth_secret_key` (offline), each base64 of 32 bytes.
- Row crypto: libsodium `crypto_secretstream_xchacha20poly1305`, one message per row; accept tags `TAG_MESSAGE` (0) and `TAG_FINAL` (3). Plaintext is a JSON string holding an `otpauth://` URI.
- Hide entries whose `codeDisplay.trashed` is true. Skip non-`totp` entries (HOTP, Steam).
- Pins: only Ente's `codeDisplay.pinned`. No pin action, no stored pins.
- No "Open Ente Auth" / "Add in …" button.
- Helper: stdlib only plus libsodium via `ctypes.util.find_library("sodium")`; run as `/usr/bin/python3 -I`.
- Secrets never leave the helper; the helper refuses to emit an entry with a `secret` field; error messages never contain decrypted data.
- DB opened read-only; nothing decrypted is written to disk.
- Error codes: `DB_MISSING`, `KEYRING_LOCKED`, `NOT_SIGNED_IN`, `DB_BUSY`, `DECRYPT_FAILED`, `DEPS_MISSING`, plus `UNSUPPORTED_SCHEMA`, `HELPER_TIMEOUT`, `OUTPUT_TOO_LARGE` (kept from the reference).
- Settings: `sortMode` (`recent` | `alpha` | `ente`), `closeOnCopy`, `notifyOnCopy`, `clipboardClearSec`, `demoMode`.
- State file `~/.local/state/lcd1232.ente-auth/prefs.json` stores last-used times only.
- TDD: every helper/model behaviour gets a failing test first.
- CI: GitHub Actions, `archlinux:latest` container, push + pull_request.

## Review Focus

1. **Wrong or rotated key** (re-login changed `auth_secret_key`): every row fails to decrypt → the panel must say "Could not decrypt Ente Auth data", not "No codes". Test in Task 5 (`test_all_rows_unreadable_is_decrypt_failed`).
2. **Messy base32 secrets** (lowercase, spaces, no `=` padding) as imported from other apps → codes still generated. Test in Task 2 (`test_b32_secret_normalisation`).
3. **Labels:** no issuer, issuer only in the `issuer` param, percent-encoded colon, non-ASCII → shown correctly. Tests in Task 3 (`test_label_variants`).
4. **App running with DB in WAL mode** (open writer connection, `-wal`/`-shm` present) → read-only open still sees committed rows. Test in Task 5 (`test_reads_wal_db_with_open_writer`).
5. **Missing or malformed `codeDisplay`** → entry still listed (unpinned, position 0), not skipped. Test in Task 3 (`test_code_display_missing_or_malformed`).

---

## File map

| File | Responsibility | Task |
|---|---|---|
| `bin/enteauth_list.py` | Helper: crypto, TOTP, URI parse, keyring, DB, CLI | 1–6 |
| `bin/enteauth-list` | sh wrapper running the helper with `/usr/bin/python3 -I` | 6 |
| `tests/support.py` | Test-only: import helper, libsodium encrypt, fixture DB | 1, 5 |
| `tests/test_crypto.py` | secretstream decrypt | 1 |
| `tests/test_totp.py` | HOTP/TOTP, base32 | 2 |
| `tests/test_otpauth.py` | URI + `codeDisplay` parsing | 3 |
| `tests/test_keyring.py` | `read_keys`, `select_vault` | 4 |
| `tests/test_entries.py` | `load_rows`, `list_entries` end to end | 5 |
| `tests/test_cli.py` | `main`, `--check`, `--demo`, wrapper | 6 |
| `Model.js` + `tests/model.test.mjs` | Panel logic (ranking, hints) | 7 |
| `bin/enteauth-prefs` + `tests/test_prefs.py` | last-used state file | 8 |
| `bin/enteauth-clipcheck` + `tests/test_clipcheck.py` | clipboard compare | 8 |
| `manifest.json`, `Service.qml`, `Panel.qml`, `EnteAuthIcon.qml`, `assets/icon.svg` | Plugin UI | 9 |
| `.github/workflows/ci.yml` | CI | 1, 6, 7, 9 |
| `README.md`, `LICENSE` | Docs, credit | 10 |

---

### Task 1: Skeleton, CI and libsodium secretstream decrypt

**Files:**
- Create: `bin/enteauth_list.py`
- Create: `tests/support.py`
- Create: `tests/test_crypto.py`
- Create: `.github/workflows/ci.yml`
- Create: `.gitignore`

**Interfaces:**
- Produces: `Err(code: str, message: str)` exception with `.code`, `.message`; `DecryptError(Exception)`; `TAG_MESSAGE = 0`, `TAG_FINAL = 3`; `sodium() -> ctypes.CDLL` (cached, raises `Err("DEPS_MISSING", ...)`); `secretstream_decrypt(key: bytes, header: bytes, ciphertext: bytes) -> bytes` (raises `DecryptError`).
- Produces (tests): `tests/support.py` exposing `ea` (the helper module) and `secretstream_encrypt(key: bytes, plaintext: bytes, tag: int = ea.TAG_FINAL) -> tuple[bytes, bytes]` returning `(header, ciphertext)`.

- [ ] **Step 1: Write `.gitignore`**

```gitignore
__pycache__/
*.pyc
```

- [ ] **Step 2: Write the test support module**

`tests/support.py`:

```python
"""Shared test helpers: import the helper from bin/ and build fixture data."""
from __future__ import annotations

import ctypes
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bin"))

import enteauth_list as ea  # noqa: E402


def secretstream_encrypt(key: bytes, plaintext: bytes, tag: int = ea.TAG_FINAL) -> tuple[bytes, bytes]:
    """Encrypt like Ente's CryptoUtil.encryptData: one secretstream message."""
    lib = ea.sodium()
    state = ctypes.create_string_buffer(lib.crypto_secretstream_xchacha20poly1305_statebytes())
    header = ctypes.create_string_buffer(lib.crypto_secretstream_xchacha20poly1305_headerbytes())
    assert lib.crypto_secretstream_xchacha20poly1305_init_push(state, header, key) == 0
    out = ctypes.create_string_buffer(len(plaintext) + lib.crypto_secretstream_xchacha20poly1305_abytes())
    out_len = ctypes.c_ulonglong(0)
    rc = lib.crypto_secretstream_xchacha20poly1305_push(
        state, out, ctypes.byref(out_len), plaintext, ctypes.c_ulonglong(len(plaintext)),
        None, ctypes.c_ulonglong(0), ctypes.c_ubyte(tag),
    )
    assert rc == 0
    return header.raw, out.raw[: out_len.value]
```

- [ ] **Step 3: Write the failing tests**

`tests/test_crypto.py`:

```python
import unittest

from support import ea, secretstream_encrypt

KEY = bytes(range(32))


class SecretstreamDecryptTest(unittest.TestCase):
    def test_round_trip_final_tag(self):
        header, ct = secretstream_encrypt(KEY, b'"otpauth://totp/x?secret=AA"', ea.TAG_FINAL)
        self.assertEqual(ea.secretstream_decrypt(KEY, header, ct), b'"otpauth://totp/x?secret=AA"')

    def test_round_trip_message_tag(self):
        # Real Ente data has rows with TAG_MESSAGE as well as TAG_FINAL.
        header, ct = secretstream_encrypt(KEY, b"hello", ea.TAG_MESSAGE)
        self.assertEqual(ea.secretstream_decrypt(KEY, header, ct), b"hello")

    def test_empty_plaintext(self):
        header, ct = secretstream_encrypt(KEY, b"")
        self.assertEqual(ea.secretstream_decrypt(KEY, header, ct), b"")

    def test_wrong_key_fails(self):
        header, ct = secretstream_encrypt(KEY, b"hello")
        with self.assertRaises(ea.DecryptError):
            ea.secretstream_decrypt(bytes(32), header, ct)

    def test_tampered_ciphertext_fails(self):
        header, ct = secretstream_encrypt(KEY, b"hello")
        bad = ct[:-1] + bytes([ct[-1] ^ 1])
        with self.assertRaises(ea.DecryptError):
            ea.secretstream_decrypt(KEY, header, bad)

    def test_bad_lengths_fail(self):
        header, ct = secretstream_encrypt(KEY, b"hello")
        for key, hdr, data in ((KEY[:31], header, ct), (KEY, header[:23], ct), (KEY, header, ct[:16])):
            with self.assertRaises(ea.DecryptError):
                ea.secretstream_decrypt(key, hdr, data)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 4: Run tests to verify they fail**

Run: `python3 -m unittest discover -s tests -v`
Expected: ERROR — `ModuleNotFoundError: No module named 'enteauth_list'`

- [ ] **Step 5: Write minimal implementation**

`bin/enteauth_list.py`:

```python
#!/usr/bin/env python3
"""Emit Ente Auth TOTP codes from the desktop app's local DB (labels + codes only).

Reads Ente Auth's encrypted SQLite DB read-only, takes the key from the Secret
Service keyring, decrypts each entry in memory with libsodium and prints a
window of upcoming codes per entry as one JSON line. Secrets never leave this
process."""
from __future__ import annotations

import ctypes
import ctypes.util

__version__ = "1.0.0"

# libsodium secretstream tags (crypto_secretstream_xchacha20poly1305_TAG_*).
TAG_MESSAGE = 0
TAG_FINAL = 3


class Err(Exception):
    """Fatal error, reported to the panel as {"error": {"code", "message"}}."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


class DecryptError(Exception):
    """One row could not be decrypted; counted, not fatal."""


_sodium: ctypes.CDLL | None = None


def sodium() -> ctypes.CDLL:
    global _sodium
    if _sodium is None:
        name = ctypes.util.find_library("sodium")
        if not name:
            raise Err("DEPS_MISSING", "libsodium not found (install package: libsodium)")
        lib = ctypes.CDLL(name)
        if lib.sodium_init() < 0:
            raise Err("DEPS_MISSING", "libsodium failed to initialise")
        for fn in ("statebytes", "abytes", "headerbytes", "keybytes"):
            getattr(lib, f"crypto_secretstream_xchacha20poly1305_{fn}").restype = ctypes.c_size_t
        _sodium = lib
    return _sodium


def secretstream_decrypt(key: bytes, header: bytes, ciphertext: bytes) -> bytes:
    """Decrypt one secretstream message (Ente's CryptoUtil.decryptData)."""
    lib = sodium()
    if len(key) != lib.crypto_secretstream_xchacha20poly1305_keybytes():
        raise DecryptError("bad key length")
    if len(header) != lib.crypto_secretstream_xchacha20poly1305_headerbytes():
        raise DecryptError("bad header length")
    abytes = lib.crypto_secretstream_xchacha20poly1305_abytes()
    if len(ciphertext) < abytes:
        raise DecryptError("ciphertext too short")
    state = ctypes.create_string_buffer(lib.crypto_secretstream_xchacha20poly1305_statebytes())
    if lib.crypto_secretstream_xchacha20poly1305_init_pull(state, header, key) != 0:
        raise DecryptError("bad header")
    out = ctypes.create_string_buffer(max(1, len(ciphertext) - abytes))
    out_len = ctypes.c_ulonglong(0)
    tag = ctypes.c_ubyte(0)
    rc = lib.crypto_secretstream_xchacha20poly1305_pull(
        state, out, ctypes.byref(out_len), ctypes.byref(tag),
        ciphertext, ctypes.c_ulonglong(len(ciphertext)), None, ctypes.c_ulonglong(0),
    )
    if rc != 0:
        raise DecryptError("authentication failed")
    if tag.value not in (TAG_MESSAGE, TAG_FINAL):
        raise DecryptError(f"unexpected tag {tag.value}")
    return out.raw[: out_len.value]
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `python3 -m unittest discover -s tests -v`
Expected: 6 tests, all PASS

- [ ] **Step 7: Add CI**

`.github/workflows/ci.yml`:

```yaml
name: CI

on:
  push:
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    container: archlinux:latest
    steps:
      - name: Install dependencies
        run: pacman -Syu --noconfirm --needed git python libsodium
      - uses: actions/checkout@v4
      - name: Python tests
        run: python -m unittest discover -s tests -v
```

- [ ] **Step 8: Commit**

```bash
chmod +x bin/enteauth_list.py
git add .gitignore bin/enteauth_list.py tests/support.py tests/test_crypto.py .github/workflows/ci.yml
git commit -m "feat: libsodium secretstream decrypt for Ente Auth rows, CI"
```

---

### Task 2: TOTP

**Files:**
- Modify: `bin/enteauth_list.py` (append after `secretstream_decrypt`; add imports)
- Create: `tests/test_totp.py`

**Interfaces:**
- Produces: `ALGORITHMS: dict[str, callable]` with keys `"SHA1"`, `"SHA256"`, `"SHA512"`; `b32decode_secret(secret: str) -> bytes` (raises `ValueError`); `hotp(key: bytes, counter: int, digits: int, algorithm: str) -> str`; `code_window(key: bytes, digits: int, algorithm: str, period: int, now: int, window: int) -> dict` returning `{"counter": int, "codes": list[str]}`.

- [ ] **Step 1: Write the failing tests**

`tests/test_totp.py`:

```python
import unittest

from support import ea

# RFC 6238 appendix B seeds and vectors (8 digits, 30 s period).
SEEDS = {
    "SHA1": b"12345678901234567890",
    "SHA256": b"12345678901234567890123456789012",
    "SHA512": b"1234567890" * 6 + b"1234",
}
VECTORS = [
    (59, "94287082", "46119246", "90693936"),
    (1111111109, "07081804", "68084774", "25091201"),
    (1111111111, "14050471", "67062674", "99943326"),
    (1234567890, "89005924", "91819424", "93441116"),
    (2000000000, "69279037", "90698825", "38618901"),
    (20000000000, "65353130", "77737706", "47863826"),
]
# RFC 4226 appendix D (6 digits, counters 0..9).
HOTP_SHA1 = ["755224", "287082", "359152", "969429", "338314",
             "254676", "287922", "162583", "399871", "520489"]


class TotpTest(unittest.TestCase):
    def test_rfc6238_vectors(self):
        for t, *expected in VECTORS:
            for alg, want in zip(("SHA1", "SHA256", "SHA512"), expected):
                with self.subTest(t=t, alg=alg):
                    self.assertEqual(ea.hotp(SEEDS[alg], t // 30, 8, alg), want)

    def test_rfc4226_vectors(self):
        self.assertEqual([ea.hotp(SEEDS["SHA1"], c, 6, "SHA1") for c in range(10)], HOTP_SHA1)

    def test_code_window(self):
        w = ea.code_window(SEEDS["SHA1"], 6, "SHA1", 30, 59, 3)
        self.assertEqual(w, {"counter": 1, "codes": ["287082", "359152", "969429"]})

    def test_b32_decode(self):
        self.assertEqual(ea.b32decode_secret("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"), SEEDS["SHA1"])

    def test_b32_secret_normalisation(self):
        # Review Focus 2: lowercase, spaces, dashes, missing padding.
        self.assertEqual(ea.b32decode_secret("gezd gnbv gy3t qojq-gezd gnbv gy3t qojq"), SEEDS["SHA1"])
        self.assertEqual(ea.b32decode_secret("JBSWY3DPEHPK3PX"), ea.b32decode_secret("JBSWY3DPEHPK3PX="))

    def test_b32_invalid(self):
        for bad in ("", "!!!!", "18"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                ea.b32decode_secret(bad)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m unittest discover -s tests -p test_totp.py -v`
Expected: FAIL/ERROR — `AttributeError: module 'enteauth_list' has no attribute 'hotp'`

- [ ] **Step 3: Write minimal implementation**

Add to the imports at the top of `bin/enteauth_list.py`:

```python
import base64
import binascii
import hashlib
import hmac
import struct
```

Append:

```python
ALGORITHMS = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}


def b32decode_secret(secret: str) -> bytes:
    """Base32 seed as typed or imported: any case, spaces/dashes, no padding."""
    s = secret.replace(" ", "").replace("-", "").upper()
    if not s:
        raise ValueError("empty secret")
    s += "=" * (-len(s) % 8)
    try:
        return base64.b32decode(s)
    except binascii.Error as e:
        raise ValueError("invalid base32 secret") from e


def hotp(key: bytes, counter: int, digits: int, algorithm: str) -> str:
    """RFC 4226 HOTP; TOTP is hotp(key, now // period, ...)."""
    mac = hmac.new(key, struct.pack(">Q", counter), ALGORITHMS[algorithm]).digest()
    offset = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def code_window(key: bytes, digits: int, algorithm: str, period: int, now: int, window: int) -> dict:
    """Codes for `window` consecutive periods, starting at the current one."""
    counter = now // period
    return {"counter": counter,
            "codes": [hotp(key, counter + k, digits, algorithm) for k in range(window)]}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m unittest discover -s tests -v`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add bin/enteauth_list.py tests/test_totp.py
git commit -m "feat: stdlib TOTP with RFC 6238 vectors"
```

---

### Task 3: otpauth URI and `codeDisplay` parsing

**Files:**
- Modify: `bin/enteauth_list.py` (append; add imports)
- Create: `tests/test_otpauth.py`

**Interfaces:**
- Consumes: `ALGORITHMS` (Task 2).
- Produces: `parse_otpauth(uri: str) -> dict | None`. Returns `None` for non-TOTP types. Raises `ValueError` for unusable input. Dict keys: `issuer: str`, `account: str`, `secret: str`, `digits: int`, `period: int`, `algorithm: str` (upper case, a key of `ALGORITHMS`), `pinned: bool`, `trashed: bool`, `position: int`.

- [ ] **Step 1: Write the failing tests**

`tests/test_otpauth.py`:

```python
import json
import unittest
from urllib.parse import quote

from support import ea


def cd(**fields) -> str:
    return quote(json.dumps(fields))


class ParseOtpauthTest(unittest.TestCase):
    def test_full_uri(self):
        uri = ("otpauth://totp/GitHub:me@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
               "&algorithm=sha256&digits=8&period=60"
               f"&codeDisplay={cd(pinned=True, trashed=False, position=4, tags=[], note='')}")
        self.assertEqual(ea.parse_otpauth(uri), {
            "issuer": "GitHub", "account": "me@example.com", "secret": "JBSWY3DPEHPK3PXP",
            "digits": 8, "period": 60, "algorithm": "SHA256",
            "pinned": True, "trashed": False, "position": 4,
        })

    def test_defaults(self):
        p = ea.parse_otpauth("otpauth://totp/acct?secret=JBSWY3DPEHPK3PXP")
        self.assertEqual((p["digits"], p["period"], p["algorithm"]), (6, 30, "SHA1"))
        self.assertEqual((p["pinned"], p["trashed"], p["position"]), (False, False, 0))

    def test_label_variants(self):
        # Review Focus 3.
        cases = {
            "otpauth://totp/me@example.com?secret=AA": ("", "me@example.com"),
            "otpauth://totp/me@example.com?secret=AA&issuer=Proton": ("Proton", "me@example.com"),
            "otpauth://totp/ACME%20Co%3Ajane%40acme.io?secret=AA": ("ACME Co", "jane@acme.io"),
            "otpauth://totp/Label%3Auser?secret=AA&issuer=Param": ("Param", "user"),
            "otpauth://totp/%D0%AF%D0%BD%D0%B4%D0%B5%D0%BA%D1%81:%C3%BCser?secret=AA": ("Яндекс", "üser"),
            "otpauth://totp/Issuer:%20spaced%20?secret=AA": ("Issuer", "spaced"),
        }
        for uri, (issuer, account) in cases.items():
            with self.subTest(uri=uri):
                p = ea.parse_otpauth(uri)
                self.assertEqual((p["issuer"], p["account"]), (issuer, account))

    def test_trashed(self):
        p = ea.parse_otpauth(f"otpauth://totp/x?secret=AA&codeDisplay={cd(trashed=True)}")
        self.assertTrue(p["trashed"])

    def test_code_display_missing_or_malformed(self):
        # Review Focus 5: still listed, unpinned, position 0.
        for tail in ("", "&codeDisplay=", "&codeDisplay=%7Bnot-json", "&codeDisplay=%5B1%2C2%5D",
                     f"&codeDisplay={cd(pinned='yes', position='3')}"):
            with self.subTest(tail=tail):
                p = ea.parse_otpauth("otpauth://totp/x?secret=AA" + tail)
                self.assertEqual((p["pinned"], p["trashed"], p["position"]), (False, False, 0))

    def test_non_totp_is_none(self):
        self.assertIsNone(ea.parse_otpauth("otpauth://hotp/x?secret=AA&counter=1"))
        self.assertIsNone(ea.parse_otpauth("otpauth://steam/x?secret=AA"))

    def test_invalid(self):
        for uri in ("https://example.com", "otpauth://totp/x", "otpauth://totp/x?secret=",
                    "otpauth://totp/x?secret=AA&digits=0", "otpauth://totp/x?secret=AA&digits=11",
                    "otpauth://totp/x?secret=AA&digits=six", "otpauth://totp/x?secret=AA&period=0",
                    "otpauth://totp/x?secret=AA&algorithm=MD5"):
            with self.subTest(uri=uri), self.assertRaises(ValueError):
                ea.parse_otpauth(uri)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m unittest discover -s tests -p test_otpauth.py -v`
Expected: ERROR — `AttributeError: ... no attribute 'parse_otpauth'`

- [ ] **Step 3: Write minimal implementation**

Add imports at the top of `bin/enteauth_list.py`:

```python
import json
from urllib.parse import parse_qs, unquote, urlparse
```

Append:

```python
def _int_param(q: dict, name: str, default: int, lo: int, hi: int) -> int:
    raw = q.get(name)
    if raw in (None, ""):
        return default
    value = int(raw)  # ValueError for non-numbers
    if not lo <= value <= hi:
        raise ValueError(f"{name} out of range")
    return value


def parse_otpauth(uri: str) -> dict | None:
    """Fields of an Ente otpauth URI; None for types other than TOTP."""
    u = urlparse(uri)
    if u.scheme != "otpauth":
        raise ValueError("not an otpauth URI")
    if u.netloc.lower() != "totp":
        return None
    q = {k: v[0] for k, v in parse_qs(u.query, keep_blank_values=True).items()}
    label = unquote(u.path[1:] if u.path.startswith("/") else u.path)
    label_issuer, account = label.split(":", 1) if ":" in label else ("", label)
    secret = q.get("secret", "").strip()
    if not secret:
        raise ValueError("missing secret")
    algorithm = (q.get("algorithm") or "SHA1").upper()
    if algorithm not in ALGORITHMS:
        raise ValueError("unsupported algorithm")
    try:
        display = json.loads(q.get("codeDisplay") or "{}")
    except ValueError:
        display = {}
    if not isinstance(display, dict):
        display = {}
    position = display.get("position")
    if not isinstance(position, int) or isinstance(position, bool):
        position = 0
    return {
        "issuer": (q.get("issuer") or label_issuer).strip(),
        "account": account.strip(),
        "secret": secret,
        "digits": _int_param(q, "digits", 6, 1, 10),
        "period": _int_param(q, "period", 30, 1, 86400),
        "algorithm": algorithm,
        "pinned": display.get("pinned") is True,
        "trashed": display.get("trashed") is True,
        "position": position,
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m unittest discover -s tests -v`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add bin/enteauth_list.py tests/test_otpauth.py
git commit -m "feat: parse Ente otpauth URIs and codeDisplay metadata"
```

---

### Task 4: Keyring and vault selection

**Files:**
- Modify: `bin/enteauth_list.py` (append; add imports and constants)
- Create: `tests/test_keyring.py`

**Interfaces:**
- Consumes: `Err` (Task 1).
- Produces: constants `DATA_DIR: Path`, `ONLINE_DB = ".ente.authenticator.db"`, `OFFLINE_DB = ".ente.offline_authenticator.db"`, `KEYRING_ACCOUNT = "io.ente.auth.secureStorage"`, `SECRET_TOOL: str`, `SECRET_TOOL_TIMEOUT_SEC = 10`, `KEYRING_MAX_BYTES = 65536`; `read_keys(secret_tool: str = SECRET_TOOL) -> dict[str, str]`; `select_vault(keys: dict, data_dir: Path) -> tuple[Path, bytes]`.

- [ ] **Step 1: Write the failing tests**

`tests/test_keyring.py`:

```python
import base64
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from support import ea

KEY = bytes(range(32))
KEY_B64 = base64.b64encode(KEY).decode()


class ReadKeysTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def tool(self, body: str) -> str:
        path = Path(self.tmp.name) / "secret-tool"
        path.write_text("#!/bin/sh\n" + body + "\n")
        path.chmod(0o755)
        return str(path)

    def assertErr(self, code, fn, *args):
        with self.assertRaises(ea.Err) as cm:
            fn(*args)
        self.assertEqual(cm.exception.code, code)

    def test_reads_json_with_fixed_argv(self):
        doc = json.dumps({"auth_secret_key": KEY_B64, "key": "x"})
        tool = self.tool(f'[ "$*" = "lookup account io.ente.auth.secureStorage" ] || exit 9\n'
                         f"printf '%s' '{doc}'")
        self.assertEqual(ea.read_keys(tool), {"auth_secret_key": KEY_B64, "key": "x"})

    def test_no_item_is_not_signed_in(self):
        self.assertErr("NOT_SIGNED_IN", ea.read_keys, self.tool("exit 1"))

    def test_empty_secret_is_locked(self):
        self.assertErr("KEYRING_LOCKED", ea.read_keys, self.tool("exit 0"))

    def test_not_json_object_is_unsupported(self):
        self.assertErr("UNSUPPORTED_SCHEMA", ea.read_keys, self.tool("printf 'nope'"))
        self.assertErr("UNSUPPORTED_SCHEMA", ea.read_keys, self.tool("printf '[1]'"))

    def test_missing_tool_is_deps_missing(self):
        self.assertErr("DEPS_MISSING", ea.read_keys, str(Path(self.tmp.name) / "absent"))

    def test_hanging_tool_times_out(self):
        with mock.patch.object(ea, "SECRET_TOOL_TIMEOUT_SEC", 0.3):
            self.assertErr("HELPER_TIMEOUT", ea.read_keys, self.tool("exec sleep 5"))

    def test_oversized_output_refused(self):
        self.assertErr("UNSUPPORTED_SCHEMA", ea.read_keys,
                       self.tool("head -c 70000 /dev/zero | tr '\\0' a"))


class SelectVaultTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def touch(self, name):
        (self.dir / name).write_bytes(b"")

    def test_online(self):
        self.touch(ea.ONLINE_DB)
        self.assertEqual(ea.select_vault({"auth_secret_key": KEY_B64}, self.dir),
                         (self.dir / ea.ONLINE_DB, KEY))

    def test_online_wins_over_offline(self):
        self.touch(ea.ONLINE_DB)
        self.touch(ea.OFFLINE_DB)
        keys = {"auth_secret_key": KEY_B64, "offline_auth_secret_key": base64.b64encode(bytes(32)).decode()}
        self.assertEqual(ea.select_vault(keys, self.dir)[0], self.dir / ea.ONLINE_DB)

    def test_offline(self):
        self.touch(ea.OFFLINE_DB)
        self.assertEqual(ea.select_vault({"offline_auth_secret_key": KEY_B64}, self.dir),
                         (self.dir / ea.OFFLINE_DB, KEY))

    def test_online_key_without_db(self):
        with self.assertRaises(ea.Err) as cm:
            ea.select_vault({"auth_secret_key": KEY_B64}, self.dir)
        self.assertEqual(cm.exception.code, "DB_MISSING")

    def test_no_keys(self):
        with self.assertRaises(ea.Err) as cm:
            ea.select_vault({"key": KEY_B64}, self.dir)
        self.assertEqual(cm.exception.code, "NOT_SIGNED_IN")

    def test_bad_key_values(self):
        self.touch(ea.ONLINE_DB)
        for bad in ("not base64!!", base64.b64encode(bytes(16)).decode()):
            with self.subTest(bad=bad), self.assertRaises(ea.Err) as cm:
                ea.select_vault({"auth_secret_key": bad}, self.dir)
            self.assertEqual(cm.exception.code, "DECRYPT_FAILED")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m unittest discover -s tests -p test_keyring.py -v`
Expected: ERROR — `AttributeError: ... no attribute 'read_keys'`

- [ ] **Step 3: Write minimal implementation**

Add imports at the top of `bin/enteauth_list.py`:

```python
import os
import subprocess
from pathlib import Path
```

Add constants below `__version__`:

```python
DATA_DIR = Path.home() / ".local/share/io.ente.auth"
ONLINE_DB = ".ente.authenticator.db"
OFFLINE_DB = ".ente.offline_authenticator.db"
KEYRING_ACCOUNT = "io.ente.auth.secureStorage"
# Absolute path first so a PATH entry can't substitute the keyring client.
SECRET_TOOL = "/usr/bin/secret-tool" if os.path.exists("/usr/bin/secret-tool") else "secret-tool"
SECRET_TOOL_TIMEOUT_SEC = 10   # a keyring unlock prompt left open, etc.
KEYRING_MAX_BYTES = 64 * 1024  # flutter_secure_storage JSON; a few hundred bytes in practice
```

Append:

```python
def read_keys(secret_tool: str = SECRET_TOOL) -> dict:
    """Ente Auth's flutter_secure_storage values from the Secret Service."""
    try:
        proc = subprocess.run(  # fixed argv, no shell
            [secret_tool, "lookup", "account", KEYRING_ACCOUNT],
            stdin=subprocess.DEVNULL, capture_output=True, timeout=SECRET_TOOL_TIMEOUT_SEC, check=False,
        )
    except FileNotFoundError as e:
        raise Err("DEPS_MISSING", "secret-tool not found (install package: libsecret)") from e
    except subprocess.TimeoutExpired as e:
        raise Err("HELPER_TIMEOUT", "secret-tool did not answer (keyring prompt open?)") from e
    out = proc.stdout
    if len(out) > KEYRING_MAX_BYTES:
        raise Err("UNSUPPORTED_SCHEMA", "keyring item too large")
    if proc.returncode != 0:
        raise Err("NOT_SIGNED_IN", "no Ente Auth item in the keyring")
    if not out.strip():
        raise Err("KEYRING_LOCKED", "empty secret — unlock the login keyring")
    try:
        keys = json.loads(out)
    except ValueError as e:
        raise Err("UNSUPPORTED_SCHEMA", "unexpected keyring item format") from e
    if not isinstance(keys, dict):
        raise Err("UNSUPPORTED_SCHEMA", "unexpected keyring item format")
    return keys


def select_vault(keys: dict, data_dir: Path) -> tuple[Path, bytes]:
    """(DB path, 32-byte key): the signed-in DB, else the offline-mode one."""
    for key_name, db_name in (("auth_secret_key", ONLINE_DB), ("offline_auth_secret_key", OFFLINE_DB)):
        value = keys.get(key_name)
        if not isinstance(value, str) or not value:
            continue
        path = data_dir / db_name
        if not path.is_file():
            raise Err("DB_MISSING", f"{db_name} not found — open Ente Auth and sign in once")
        try:
            key = base64.b64decode(value, validate=True)
        except binascii.Error as e:
            raise Err("DECRYPT_FAILED", f"{key_name} is not base64") from e
        if len(key) != 32:
            raise Err("DECRYPT_FAILED", f"{key_name} has unexpected length {len(key)}")
        return path, key
    raise Err("NOT_SIGNED_IN", "no Ente Auth key in the keyring")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m unittest discover -s tests -v`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add bin/enteauth_list.py tests/test_keyring.py
git commit -m "feat: read Ente Auth key from keyring and pick online/offline DB"
```

---

### Task 5: DB loading and `list_entries`

**Files:**
- Modify: `bin/enteauth_list.py` (append; add imports and constants)
- Modify: `tests/support.py` (append fixture builders)
- Create: `tests/test_entries.py`

**Interfaces:**
- Consumes: `secretstream_decrypt`, `DecryptError` (Task 1); `b32decode_secret`, `code_window` (Task 2); `parse_otpauth` (Task 3); `read_keys`, `select_vault`, `DATA_DIR`, `ONLINE_DB`, `OFFLINE_DB` (Task 4).
- Produces: constants `MAX_ENTRIES = 1000`, `MAX_LABEL_CHARS = 256`, `MAX_ID_CHARS = 128`, `DB_BUSY_RETRY_SEC = 0.2`; `iso_time(epoch: int) -> str`; `load_rows(db_path: Path) -> list[tuple]` of `(id, generated_id, encrypted_data, header)`; `list_entries(window: int, now: int | None = None, data_dir: Path | None = None, keys: dict | None = None) -> dict`. Return shape: `{"ok": True, "updatedAt": str, "entries": [entry...], "skipped": int, "error": None}`. Each entry has `id`, `issuer`, `account`, `period`, `digits`, `pinned`, `position`, `counter`, `codes`.
- Produces (tests): in `tests/support.py`: `KEY: bytes`, `KEY_B64: str`, `RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"`, `otpauth(label="GitHub:me@example.com", secret=RFC_SECRET, issuer="GitHub", code_display=None, kind="totp", **params) -> str`, `encrypt_row(uri: str, key: bytes = KEY, tag: int = ea.TAG_FINAL) -> tuple[str, str]` returning `(encryptedData_b64, header_b64)`, `make_db(path: Path, rows: list[tuple], wal: bool = False) -> None` where rows are `(id_or_None, encryptedData_b64, header_b64)`.

- [ ] **Step 1: Extend test support**

Append to `tests/support.py` (and add `import base64`, `import json`, `import sqlite3`, `from urllib.parse import quote, urlencode` to its imports):

```python
KEY = bytes(range(32))
KEY_B64 = base64.b64encode(KEY).decode()
# RFC 4226 seed; at now=59 (counter 1) the 6-digit codes are 287082, 359152, 969429, ...
RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

# Ente Auth 4.4.24 schema (from the real DB).
SCHEMA = """CREATE TABLE entities (
  _generatedID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
  id TEXT,
  encryptedData TEXT NOT NULL,
  header TEXT NOT NULL,
  createdAt INTEGER NOT NULL,
  updatedAt INTEGER NOT NULL,
  shouldSync INTEGER DEFAULT 0,
  UNIQUE(id)
)"""


def otpauth(label="GitHub:me@example.com", secret=RFC_SECRET, issuer="GitHub",
            code_display=None, kind="totp", **params) -> str:
    q = {"secret": secret, "issuer": issuer, **params}
    if code_display is not None:
        q["codeDisplay"] = json.dumps(code_display)
    query = urlencode({k: v for k, v in q.items() if v is not None})
    return f"otpauth://{kind}/{quote(label)}?{query}"


def encrypt_row(uri: str, key: bytes = KEY, tag: int = ea.TAG_FINAL) -> tuple[str, str]:
    header, ct = secretstream_encrypt(key, json.dumps(uri).encode(), tag)
    return base64.b64encode(ct).decode(), base64.b64encode(header).decode()


def make_db(path: Path, rows: list[tuple], wal: bool = False) -> None:
    con = sqlite3.connect(path)
    if wal:
        con.execute("PRAGMA journal_mode=WAL")
    con.execute(SCHEMA)
    con.executemany(
        "INSERT INTO entities (id, encryptedData, header, createdAt, updatedAt, shouldSync)"
        " VALUES (?, ?, ?, 0, 0, 0)", rows)
    con.commit()
    con.close()
```

- [ ] **Step 2: Write the failing tests**

`tests/test_entries.py`:

```python
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from support import KEY_B64, ea, encrypt_row, make_db, otpauth

KEYS = {"auth_secret_key": KEY_B64}


class ListEntriesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.db = self.dir / ea.ONLINE_DB

    def run_list(self, window=3, now=59):
        return ea.list_entries(window, now=now, data_dir=self.dir, keys=KEYS)

    def test_end_to_end(self):
        make_db(self.db, [
            ("ent-1", *encrypt_row(otpauth(code_display={"pinned": True, "position": 2}))),
            (None, *encrypt_row(otpauth("Acme:bob", issuer="Acme"), tag=ea.TAG_MESSAGE)),
        ])
        out = self.run_list()
        self.assertEqual((out["ok"], out["skipped"], out["error"]), (True, 0, None))
        self.assertEqual(out["updatedAt"], "1970-01-01T00:00:59Z")
        self.assertEqual(out["entries"][0], {
            "id": "ent-1", "issuer": "GitHub", "account": "me@example.com",
            "period": 30, "digits": 6, "pinned": True, "position": 2,
            "counter": 1, "codes": ["287082", "359152", "969429"],
        })
        # Unsynced row (id NULL) falls back to the local row id.
        self.assertEqual(out["entries"][1]["id"], "local-2")
        self.assertEqual(out["entries"][1]["issuer"], "Acme")

    def test_never_emits_secret(self):
        make_db(self.db, [("a", *encrypt_row(otpauth()))])
        out = self.run_list()
        self.assertNotIn("secret", out["entries"][0])
        self.assertNotIn("GEZDGNBV", repr(out))

    def test_trashed_and_non_totp_hidden_not_skipped(self):
        make_db(self.db, [
            ("a", *encrypt_row(otpauth(code_display={"trashed": True}))),
            ("b", *encrypt_row(otpauth(kind="hotp", counter="0"))),
            ("c", *encrypt_row(otpauth("Keep:me"))),
        ])
        out = self.run_list()
        self.assertEqual([e["id"] for e in out["entries"]], ["c"])
        self.assertEqual(out["skipped"], 0)

    def test_corrupted_row_is_skipped(self):
        data, header = encrypt_row(otpauth())
        make_db(self.db, [
            ("good", data, header),
            ("bad", data[:-4] + "AAAA", header),
            ("notb64", "!!!", header),
            ("badsecret", *encrypt_row(otpauth(secret="1111"))),
            ("notstring", *encrypt_row(["not", "a", "uri"])),
        ])
        out = self.run_list()
        self.assertEqual([e["id"] for e in out["entries"]], ["good"])
        self.assertEqual(out["skipped"], 4)

    def test_all_rows_unreadable_is_decrypt_failed(self):
        # Review Focus 1: wrong key must not look like an empty vault.
        make_db(self.db, [("a", *encrypt_row(otpauth(), key=bytes(32)))])
        with self.assertRaises(ea.Err) as cm:
            self.run_list()
        self.assertEqual(cm.exception.code, "DECRYPT_FAILED")

    def test_empty_db_is_ok(self):
        make_db(self.db, [])
        self.assertEqual(self.run_list()["entries"], [])

    def test_labels_truncated(self):
        make_db(self.db, [("a", *encrypt_row(otpauth("I" * 300 + ":" + "A" * 300, issuer=None)))])
        e = self.run_list()["entries"][0]
        self.assertEqual((len(e["issuer"]), len(e["account"])), (256, 256))

    def test_missing_db_checked_before_keyring(self):
        with mock.patch.object(ea, "read_keys", side_effect=AssertionError("keyring touched")):
            with self.assertRaises(ea.Err) as cm:
                ea.list_entries(3, now=59, data_dir=self.dir)
        self.assertEqual(cm.exception.code, "DB_MISSING")

    def test_reads_keyring_when_keys_not_given(self):
        make_db(self.db, [("a", *encrypt_row(otpauth()))])
        with mock.patch.object(ea, "read_keys", return_value=KEYS):
            out = ea.list_entries(3, now=59, data_dir=self.dir)
        self.assertEqual(len(out["entries"]), 1)

    def test_offline_db(self):
        make_db(self.dir / ea.OFFLINE_DB, [("a", *encrypt_row(otpauth()))])
        out = ea.list_entries(3, now=59, data_dir=self.dir, keys={"offline_auth_secret_key": KEY_B64})
        self.assertEqual(len(out["entries"]), 1)

    def test_reads_wal_db_with_open_writer(self):
        # Review Focus 4: the app keeps the DB open in WAL mode.
        make_db(self.db, [("a", *encrypt_row(otpauth()))], wal=True)
        writer = sqlite3.connect(self.db)
        self.addCleanup(writer.close)
        writer.execute("INSERT INTO entities (id, encryptedData, header, createdAt, updatedAt)"
                       " VALUES (?, ?, ?, 0, 0)", ("b", *encrypt_row(otpauth("New:one"))))
        writer.commit()
        self.assertEqual([e["id"] for e in self.run_list()["entries"]], ["a", "b"])

    def test_locked_db_retries_then_busy(self):
        make_db(self.db, [("a", *encrypt_row(otpauth()))])
        locker = sqlite3.connect(self.db, isolation_level=None)
        self.addCleanup(locker.close)
        locker.execute("BEGIN EXCLUSIVE")
        with mock.patch.object(ea, "DB_BUSY_RETRY_SEC", 0), \
             mock.patch.object(ea.time, "sleep", wraps=ea.time.sleep) as sleep:
            with self.assertRaises(ea.Err) as cm:
                self.run_list()
        self.assertEqual(cm.exception.code, "DB_BUSY")
        self.assertEqual(sleep.call_count, 1)

    def test_wrong_schema(self):
        con = sqlite3.connect(self.db)
        con.execute("CREATE TABLE other (x)")
        con.close()
        with self.assertRaises(ea.Err) as cm:
            self.run_list()
        self.assertEqual(cm.exception.code, "UNSUPPORTED_SCHEMA")

    def test_too_many_rows(self):
        row = ("x", *encrypt_row(otpauth()))
        make_db(self.db, [(f"id{i}", row[1], row[2]) for i in range(3)])
        with mock.patch.object(ea, "MAX_ENTRIES", 2), self.assertRaises(ea.Err) as cm:
            self.run_list()
        self.assertEqual(cm.exception.code, "OUTPUT_TOO_LARGE")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `python3 -m unittest discover -s tests -p test_entries.py -v`
Expected: ERROR — `AttributeError: ... no attribute 'list_entries'`

- [ ] **Step 4: Write minimal implementation**

Add imports at the top of `bin/enteauth_list.py`:

```python
import sqlite3
import time
```

Add constants below the keyring constants:

```python
MAX_ENTRIES = 1000
MAX_LABEL_CHARS = 256          # issuer / account, truncated for display
MAX_ID_CHARS = 128
DB_BUSY_RETRY_SEC = 0.2
```

Append:

```python
def iso_time(epoch: int) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


def load_rows(db_path: Path) -> list[tuple]:
    """(id, _generatedID, encryptedData, header) per row, read-only."""
    for attempt in (0, 1):
        try:
            con = sqlite3.connect(db_path.as_uri() + "?mode=ro", uri=True, timeout=0)
            try:
                return con.execute(
                    "SELECT id, _generatedID, encryptedData, header FROM entities ORDER BY _generatedID"
                ).fetchall()
            finally:
                con.close()
        except sqlite3.OperationalError as e:
            text = str(e)
            if "locked" in text or "busy" in text:
                if attempt == 0:
                    time.sleep(DB_BUSY_RETRY_SEC)
                    continue
                raise Err("DB_BUSY", "Ente Auth database is busy") from e
            if "no such table" in text or "no such column" in text:
                raise Err("UNSUPPORTED_SCHEMA", "unexpected Ente Auth database layout") from e
            raise Err("DB_MISSING", f"cannot read Ente Auth database ({type(e).__name__})") from e
        except sqlite3.DatabaseError as e:
            raise Err("UNSUPPORTED_SCHEMA", f"not a readable database ({type(e).__name__})") from e
    raise AssertionError("unreachable")


def list_entries(window: int, now: int | None = None, data_dir: Path | None = None,
                 keys: dict | None = None) -> dict:
    data_dir = DATA_DIR if data_dir is None else data_dir
    now = int(time.time()) if now is None else now
    # Before touching the keyring: no DB means Ente Auth was never set up here.
    if not any((data_dir / name).is_file() for name in (ONLINE_DB, OFFLINE_DB)):
        raise Err("DB_MISSING", f"no Ente Auth database in {data_dir}")
    db_path, key = select_vault(read_keys() if keys is None else keys, data_dir)
    rows = load_rows(db_path)
    if len(rows) > MAX_ENTRIES:
        raise Err("OUTPUT_TOO_LARGE", f"more than {MAX_ENTRIES} entries")
    entries: list[dict] = []
    skipped = 0
    for entity_id, generated_id, data, header in rows:
        try:
            plain = secretstream_decrypt(
                key, base64.b64decode(header, validate=True), base64.b64decode(data, validate=True))
            uri = json.loads(plain.decode("utf-8"))
            if not isinstance(uri, str):
                raise ValueError("payload is not a string")
            otp = parse_otpauth(uri)
            if otp is None or otp["trashed"]:
                continue
            seed = b32decode_secret(otp["secret"])
        except (DecryptError, ValueError):  # binascii/JSON/Unicode errors are ValueErrors
            skipped += 1
            continue
        entries.append({
            "id": (str(entity_id) if entity_id else f"local-{generated_id}")[:MAX_ID_CHARS],
            "issuer": otp["issuer"][:MAX_LABEL_CHARS],
            "account": otp["account"][:MAX_LABEL_CHARS],
            "period": otp["period"],
            "digits": otp["digits"],
            "pinned": otp["pinned"],
            "position": otp["position"],
            **code_window(seed, otp["digits"], otp["algorithm"], otp["period"], now, window),
        })
    if rows and skipped == len(rows):
        raise Err("DECRYPT_FAILED", "no entry could be decrypted (wrong key?)")
    return {"ok": True, "updatedAt": iso_time(now), "entries": entries, "skipped": skipped, "error": None}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `python3 -m unittest discover -s tests -v`
Expected: all PASS

- [ ] **Step 6: Commit**

```bash
git add bin/enteauth_list.py tests/support.py tests/test_entries.py
git commit -m "feat: read and decrypt Ente Auth entities into code windows"
```

---

### Task 6: CLI entry point and wrapper

**Files:**
- Modify: `bin/enteauth_list.py` (append; add imports and constants)
- Create: `bin/enteauth-list`
- Create: `tests/test_cli.py`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: `list_entries`, `iso_time`, `Err` (Task 5); `b32decode_secret`, `code_window` (Task 2).
- Produces: `fail(code: str, message: str) -> dict`; `emit(payload: dict) -> None`; `check(data_dir: Path | None = None, keys: dict | None = None) -> dict` (`check` key holds `{"entries": int, "skipped": int}`); `demo(window: int, now: int | None = None) -> dict`; `main(argv: list[str] | None = None) -> int`. Command line: `bin/enteauth-list [--check] [--demo] [--window N] [--version]`. Output: one JSON line on stdout, `{"ok", "updatedAt", "entries", "error"[, "skipped", "demo", "check"]}`.

- [ ] **Step 1: Write the failing tests**

`tests/test_cli.py`:

```python
import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from support import KEY_B64, ROOT, ea, encrypt_row, make_db, otpauth

WRAPPER = ROOT / "bin" / "enteauth-list"


def run_main(*argv):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = ea.main(list(argv))
    lines = buf.getvalue().splitlines()
    assert len(lines) == 1, lines
    return rc, json.loads(lines[0])


class MainTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        make_db(self.dir / ea.ONLINE_DB, [("a", *encrypt_row(otpauth()))])
        patches = [mock.patch.object(ea, "DATA_DIR", self.dir),
                   mock.patch.object(ea, "read_keys", return_value={"auth_secret_key": KEY_B64})]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def test_lists_codes(self):
        rc, out = run_main("--window", "4")
        self.assertEqual(rc, 0)
        self.assertEqual(len(out["entries"][0]["codes"]), 4)

    def test_window_is_clamped(self):
        self.assertEqual(len(run_main("--window", "999")[1]["entries"][0]["codes"]), ea.MAX_WINDOW)
        self.assertEqual(len(run_main("--window", "0")[1]["entries"][0]["codes"]), 1)

    def test_check_prints_counts_only(self):
        rc, out = run_main("--check")
        self.assertEqual(rc, 0)
        self.assertEqual(out["entries"], [])
        self.assertEqual(out["check"], {"entries": 1, "skipped": 0})

    def test_err_becomes_json(self):
        with mock.patch.object(ea, "read_keys", side_effect=ea.Err("KEYRING_LOCKED", "locked")):
            rc, out = run_main()
        self.assertEqual(rc, 1)
        self.assertEqual((out["ok"], out["entries"], out["error"]["code"]), (False, [], "KEYRING_LOCKED"))

    def test_unexpected_exception_hides_message(self):
        with mock.patch.object(ea, "list_entries", side_effect=RuntimeError("SECRET=JBSWY3DP")):
            rc, out = run_main()
        self.assertEqual(rc, 1)
        self.assertEqual(out["error"], {"code": "DECRYPT_FAILED", "message": "internal error (RuntimeError)"})

    def test_refuses_secret_field(self):
        leaky = {"ok": True, "updatedAt": "", "entries": [{"id": "a", "secret": "X"}], "skipped": 0, "error": None}
        with mock.patch.object(ea, "list_entries", return_value=leaky):
            rc, out = run_main()
        self.assertEqual((rc, out["error"]["code"]), (1, "DECRYPT_FAILED"))

    def test_oversized_output_replaced(self):
        with mock.patch.object(ea, "MAX_OUTPUT_BYTES", 50):
            rc, out = run_main()
        self.assertEqual(out["error"]["code"], "OUTPUT_TOO_LARGE")


class DemoTest(unittest.TestCase):
    def test_demo_never_reads_vault(self):
        with mock.patch.object(ea, "list_entries", side_effect=AssertionError("vault read")):
            rc, out = run_main("--demo", "--window", "2")
        self.assertEqual(rc, 0)
        self.assertTrue(out["demo"])
        self.assertGreaterEqual(len(out["entries"]), 5)
        self.assertTrue(all(len(e["codes"]) == 2 for e in out["entries"]))
        self.assertTrue(any(e["pinned"] for e in out["entries"]))


class WrapperTest(unittest.TestCase):
    def test_wrapper_runs_demo(self):
        proc = subprocess.run([str(WRAPPER), "--demo", "--window", "1"], capture_output=True, text=True, timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(json.loads(proc.stdout)["demo"])

    def test_wrapper_version(self):
        proc = subprocess.run([str(WRAPPER), "--version"], capture_output=True, text=True, timeout=30)
        self.assertEqual(proc.stdout.strip(), f"enteauth-list {ea.__version__}")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m unittest discover -s tests -p test_cli.py -v`
Expected: ERROR — `AttributeError: ... no attribute 'main'` and wrapper `FileNotFoundError`

- [ ] **Step 3: Write minimal implementation**

Add imports at the top of `bin/enteauth_list.py`:

```python
import argparse
import signal
import sys
```

Add constants below `DB_BUSY_RETRY_SEC`:

```python
HELPER_TIMEOUT_SEC = 20        # whole run; SIGALRM -> HELPER_TIMEOUT JSON
MAX_MESSAGE_CHARS = 200
MAX_OUTPUT_BYTES = 1024 * 1024 # omarchy-shell buffers our whole stdout
DEFAULT_WINDOW = 10
MAX_WINDOW = 20
```

Append:

```python
def fail(code: str, message: str) -> dict:
    return {"ok": False, "updatedAt": iso_time(int(time.time())), "entries": [],
            "error": {"code": code, "message": str(message)[:MAX_MESSAGE_CHARS]}}


def emit(payload: dict) -> None:
    """Print payload as one JSON line, never more than MAX_OUTPUT_BYTES."""
    out = json.dumps(payload, separators=(",", ":"))
    if len(out.encode("utf-8")) > MAX_OUTPUT_BYTES:
        out = json.dumps(fail("OUTPUT_TOO_LARGE", f"output over {MAX_OUTPUT_BYTES} bytes"),
                         separators=(",", ":"))
    print(out)


def check(data_dir: Path | None = None, keys: dict | None = None) -> dict:
    """Diagnose the setup; prints counts, never codes."""
    payload = list_entries(1, data_dir=data_dir, keys=keys)
    return {"ok": True, "updatedAt": payload["updatedAt"], "entries": [], "error": None,
            "check": {"entries": len(payload["entries"]), "skipped": payload["skipped"]}}


# Fake accounts for screenshots. Well-known public test seeds, not real ones.
DEMO_ACCOUNTS = [
    ("GitHub", "octocat@example.com", "JBSWY3DPEHPK3PXP", 6, True),
    ("Ente", "demo@ente.io", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 6, False),
    ("Google", "jane.doe@example.com", "KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ", 6, False),
    ("AWS", "root@example.org", "MFRGGZDFMZTWQ2LKNNWG23TPOBYXE43U", 6, False),
    ("Discord", "jane#0001", "ONSWG4TFORZWK3DUMVZXG5DFON2A", 6, False),
    ("Tailscale", "jane@example.net", "OBQXG43XN5ZGIZLYMFWXA3DF", 8, False),
]


def demo(window: int, now: int | None = None) -> dict:
    now = int(time.time()) if now is None else now
    entries = []
    for i, (issuer, account, seed, digits, pinned) in enumerate(DEMO_ACCOUNTS):
        entries.append({
            "id": f"demo-{i}", "issuer": issuer, "account": account, "period": 30,
            "digits": digits, "pinned": pinned, "position": i,
            **code_window(b32decode_secret(seed), digits, "SHA1", 30, now, window),
        })
    return {"ok": True, "demo": True, "updatedAt": iso_time(now), "entries": entries,
            "skipped": 0, "error": None}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true",
                    help="verify keyring and database access; prints counts, no codes")
    ap.add_argument("--demo", action="store_true",
                    help="print fake demo accounts (for screenshots); never touches the vault")
    ap.add_argument("--window", type=int, default=DEFAULT_WINDOW,
                    help=f"codes per entry, current one first (1-{MAX_WINDOW})")
    ap.add_argument("--version", action="version", version=f"enteauth-list {__version__}")
    args = ap.parse_args(argv)
    window = max(1, min(MAX_WINDOW, args.window))
    try:
        if args.demo:
            emit(demo(window))
            return 0
        if args.check:
            emit(check())
            return 0
        payload = list_entries(window)
        if any("secret" in e for e in payload["entries"]):
            raise Err("DECRYPT_FAILED", "refusing to emit secret field")
        emit(payload)
        return 0
    except Err as e:
        emit(fail(e.code, e.message))
        return 1
    except Exception as e:  # noqa: BLE001 - fail closed with a JSON error
        # Only the exception type: its text could quote decrypted data.
        emit(fail("DECRYPT_FAILED", f"internal error ({type(e).__name__})"))
        return 1


def _exit_on_signal(signum, _frame):
    raise SystemExit(128 + signum)


def _on_alarm(_signum, _frame):
    raise Err("HELPER_TIMEOUT", f"helper took longer than {HELPER_TIMEOUT_SEC} s")


if __name__ == "__main__":
    for _sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        signal.signal(_sig, _exit_on_signal)
    signal.signal(signal.SIGALRM, _on_alarm)
    signal.alarm(HELPER_TIMEOUT_SEC)
    sys.exit(main())
```

`bin/enteauth-list`:

```sh
#!/bin/sh
# Runs the helper with the system Python in isolated mode: no user site
# packages, no environment-driven imports (the helper is stdlib only).
HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd) || exit 1
exec /usr/bin/python3 -I "$HERE/enteauth_list.py" "$@"
```

Run: `chmod +x bin/enteauth-list`

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m unittest discover -s tests -v`
Expected: all PASS

- [ ] **Step 5: Add shellcheck to CI**

In `.github/workflows/ci.yml`, change the install line to
`run: pacman -Syu --noconfirm --needed git python libsodium shellcheck`
and append the step:

```yaml
      - name: Shellcheck
        run: shellcheck bin/enteauth-list
```

Run locally if available: `shellcheck bin/enteauth-list` (install with `sudo pacman -S shellcheck` if missing). Expected: no output.

- [ ] **Step 6: Commit**

```bash
git add bin/enteauth_list.py bin/enteauth-list tests/test_cli.py .github/workflows/ci.yml
git commit -m "feat: enteauth-list CLI with --check, --demo and JSON errors"
```

---

### Task 7: `Model.js` (panel logic) with node tests

**Files:**
- Create: `Model.js` (from the reference `Model.js`, changed as below)
- Create: `tests/model.test.mjs`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: the helper JSON from Task 6 (entries carry `pinned`, `position`; top level carries `skipped`).
- Produces (for Task 9's QML): `parseList(raw)`, `formatCode(code)`, `entryKey(entry)`, `codeState(entry, nowSec)`, `refreshAt(entries)`, `matchScore(entry, q)`, `rankEntries(entries, query, used, sortMode) -> [{entry, pinned}]`, `errorHint(error) -> string`, `skippedHint(n) -> string`, `statusHint(s) -> string` where `s = {refreshing, ok, error, total, shown, query, skipped}`.

- [ ] **Step 1: Write the failing tests**

`tests/model.test.mjs`:

```js
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
  const rows = M.rankEntries([e("GitHub"), e("Bitbucket", { pinned: true })], "git", {}, "alpha")
  assert.deepEqual(ids(rows), ["github", "bitbucket"])
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `node --test tests/model.test.mjs`
Expected: FAIL — `ENOENT: no such file or directory ... Model.js`

- [ ] **Step 3: Implement `Model.js`**

Copy `Model.js` from the reference, then make exactly these changes:

1. Replace the comment above `entryKey` with `// Stable key for recent-use. The Ente entity id when there is one.`
2. Replace the whole `rankEntries` function with:

```js
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
```

3. Replace the `hints` object inside `errorHint` with:

```js
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
```

4. Append:

```js
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `node --test tests/model.test.mjs`
Expected: all tests pass

- [ ] **Step 5: Add node tests to CI**

In `.github/workflows/ci.yml`, add `nodejs` to the pacman install list and append:

```yaml
      - name: Model tests
        run: node --test tests/model.test.mjs
```

- [ ] **Step 6: Commit**

```bash
git add Model.js tests/model.test.mjs .github/workflows/ci.yml
git commit -m "feat: panel model with Ente pins, ente sort and status hints"
```

---

### Task 8: Prefs and clipboard-check helpers

**Files:**
- Create: `bin/enteauth-prefs` (from the reference `bin/protonauth-prefs`, changed)
- Create: `bin/enteauth-clipcheck` (from the reference `bin/protonauth-clipcheck`, renamed)
- Create: `tests/test_prefs.py`
- Create: `tests/test_clipcheck.py`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Produces: `bin/enteauth-prefs read` prints `{"used": {key: epoch}}`; `bin/enteauth-prefs write` reads that document on stdin. State dir `$XDG_STATE_HOME/lcd1232.ente-auth/` (default `~/.local/state/lcd1232.ente-auth/`). `bin/enteauth-clipcheck` reads a code on stdin and prints `match` or `nomatch`.

- [ ] **Step 1: Write the failing tests**

`tests/test_prefs.py`:

```python
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from support import ROOT

PREFS = ROOT / "bin" / "enteauth-prefs"


class PrefsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.env = {**os.environ, "XDG_STATE_HOME": self.tmp.name}
        self.dir = Path(self.tmp.name) / "lcd1232.ente-auth"

    def prefs(self, cmd, stdin=""):
        return subprocess.run([str(PREFS), cmd], input=stdin, capture_output=True, text=True,
                              env=self.env, timeout=30)

    def test_read_empty(self):
        self.assertEqual(json.loads(self.prefs("read").stdout), {"used": {}})

    def test_round_trip_drops_pins_and_bad_values(self):
        doc = {"pins": {"id:a": True}, "used": {"id:a": 100, "id:b": "x", "id:c": True, "": 5}}
        self.assertEqual(self.prefs("write", json.dumps(doc)).returncode, 0)
        self.assertEqual(json.loads(self.prefs("read").stdout), {"used": {"id:a": 100}})
        self.assertEqual(oct(self.dir.stat().st_mode & 0o777), "0o700")

    def test_refuses_shared_dir(self):
        self.dir.mkdir(mode=0o755)
        self.dir.chmod(0o755)
        self.assertNotEqual(self.prefs("write", '{"used":{}}').returncode, 0)

    def test_does_not_follow_symlinked_file(self):
        self.dir.mkdir(mode=0o700)
        target = Path(self.tmp.name) / "elsewhere.json"
        target.write_text('{"used":{"id:x":1}}')
        (self.dir / "prefs.json").symlink_to(target)
        self.assertEqual(json.loads(self.prefs("read").stdout), {"used": {}})

    def test_usage(self):
        self.assertEqual(self.prefs("bogus").returncode, 2)


if __name__ == "__main__":
    unittest.main()
```

`tests/test_clipcheck.py`:

```python
import subprocess
import unittest

from support import ROOT

CLIPCHECK = ROOT / "bin" / "enteauth-clipcheck"


class ClipcheckTest(unittest.TestCase):
    def test_refuses_non_digit_input_without_touching_clipboard(self):
        for bad in ("", "12a456", "12345678901"):
            with self.subTest(bad=bad):
                proc = subprocess.run([str(CLIPCHECK)], input=bad, capture_output=True, text=True, timeout=10)
                self.assertEqual(proc.stdout, "nomatch\n")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m unittest discover -s tests -p "test_[pc]*.py" -v`
Expected: ERROR — `FileNotFoundError` for `bin/enteauth-prefs` and `bin/enteauth-clipcheck`

- [ ] **Step 3: Implement**

`bin/enteauth-clipcheck`: copy the reference `bin/protonauth-clipcheck`. Replace the first two comment lines with:

```sh
# enteauth-clipcheck: does the Wayland clipboard still hold the code we copied?
# From navjottomer/omarchy-proton-authenticator (MIT), based on io.github.mapski.proton-authenticator.
```

Leave everything else unchanged. `chmod +x bin/enteauth-clipcheck`.

`bin/enteauth-prefs`: copy the reference `bin/protonauth-prefs`, then:

1. Docstring: replace `(pinned and recently used accounts)` with `(recently used accounts)`, `protonauth-prefs` with `enteauth-prefs` (3 places), `navjottomer.proton-authenticator` with `lcd1232.ente-auth`, and the last paragraph with: `Output and input are bounded and validated: only {"used": {key: epoch-seconds}} with short string keys survives.`
2. `APP_ID = "lcd1232.ente-auth"`
3. `EMPTY = {"used": {}}`
4. Replace `clean` with:

```python
def clean(data: object) -> dict:
    """Keep only well-formed used entries."""
    out = {"used": {}}
    if not isinstance(data, dict):
        return out
    used = data.get("used")
    if isinstance(used, dict):
        for k, v in list(used.items())[:MAX_KEYS]:
            if (isinstance(k, str) and 0 < len(k) <= MAX_KEY_CHARS
                    and isinstance(v, int) and not isinstance(v, bool) and 0 <= v < 2**41):
                out["used"][k] = v
    return out
```

5. In `main`, the usage line: `print("usage: enteauth-prefs read|write", file=sys.stderr)`
6. `dict(EMPTY)` is a shallow copy that shares the inner `{}`; replace every `dict(EMPTY)` with `{"used": {}}`.

`chmod +x bin/enteauth-prefs`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m unittest discover -s tests -v`
Expected: all PASS

- [ ] **Step 5: Extend shellcheck in CI**

In `.github/workflows/ci.yml`, change the Shellcheck step to:
`run: shellcheck bin/enteauth-list bin/enteauth-clipcheck`
Run locally: `shellcheck bin/enteauth-list bin/enteauth-clipcheck` → no output.

- [ ] **Step 6: Commit**

```bash
git add bin/enteauth-prefs bin/enteauth-clipcheck tests/test_prefs.py tests/test_clipcheck.py .github/workflows/ci.yml
git commit -m "feat: last-used prefs store and clipboard check helpers"
```

---

### Task 9: Plugin UI (manifest, Service, Panel, icon)

QML can't run in CI. This task is verified with `omarchy plugin validate` and by hand.

**Files:**
- Create: `manifest.json`
- Create: `Service.qml` (from reference, changed)
- Create: `Panel.qml` (from reference, changed)
- Create: `EnteAuthIcon.qml`
- Create: `assets/icon.svg`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: `bin/enteauth-list` (Task 6), `Model.*` (Task 7), `bin/enteauth-prefs`, `bin/enteauth-clipcheck` (Task 8).
- Produces: bar widget `lcd1232.ente-auth`; IPC `omarchy-shell lcd1232.ente-auth toggle|open|close|refresh|clearClipboard`.

- [ ] **Step 1: Write `manifest.json`**

```json
{
  "schemaVersion": 1,
  "id": "lcd1232.ente-auth",
  "name": "Ente Auth",
  "version": "1.0.0",
  "author": "lcd1232",
  "license": "MIT",
  "description": "Ente Auth TOTP codes in the Omarchy bar: type to search, Enter to copy, Ente-pinned and recently used first. Reads the desktop app's local data; no network.",
  "kinds": ["bar-widget"],
  "entryPoints": { "barWidget": "Panel.qml" },
  "barWidget": {
    "displayName": "Ente Auth",
    "description": "Search and copy TOTP codes from Ente Auth.",
    "category": "Security",
    "aliases": ["ente", "ente-auth", "authenticator", "2fa", "totp", "otp"],
    "allowMultiple": false,
    "defaultSection": "right",
    "defaults": {
      "sortMode": "recent",
      "closeOnCopy": true,
      "notifyOnCopy": true,
      "clipboardClearSec": 20,
      "demoMode": false
    },
    "schema": [
      { "key": "sortMode", "type": "enum", "label": "Sort accounts by",
        "options": ["recent", "alpha", "ente"], "defaultValue": "recent" },
      { "key": "closeOnCopy", "type": "boolean", "label": "Close the panel after copying a code", "defaultValue": true },
      { "key": "notifyOnCopy", "type": "boolean", "label": "Show a notification after copying", "defaultValue": true },
      { "key": "clipboardClearSec", "type": "integer",
        "label": "Clear copied code from clipboard after (seconds, 0 = never)",
        "min": 0, "max": 600, "step": 5, "defaultValue": 20 },
      { "key": "demoMode", "type": "boolean", "label": "Demo mode (fake accounts, for screenshots)", "defaultValue": false }
    ]
  }
}
```

- [ ] **Step 2: Write the icon**

`assets/icon.svg` (a generic shield with keyhole, not Ente's logo):

```svg
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 36 36" width="36" height="36">
  <path fill="currentColor" fill-rule="evenodd"
    d="M18 2 L31 7 V17 C31 25.5 25.6 31.6 18 34 C10.4 31.6 5 25.5 5 17 V7 Z M18 11 A4 4 0 0 0 16.2 18.6 L15 25 H21 L19.8 18.6 A4 4 0 0 0 18 11 Z"/>
</svg>
```

`EnteAuthIcon.qml`:

```qml
import QtQuick
import QtQuick.Shapes
import qs.Commons

// Shield-and-keyhole mark in one colour, so it follows the theme like the
// built-in bar icons. Same shape as assets/icon.svg (36x36 viewBox).
Item {
  id: root

  property real iconSize: Style.font.icon
  property color color: Color.foreground
  property real iconOpacity: 1.0

  width: iconSize
  height: iconSize
  implicitWidth: iconSize
  implicitHeight: iconSize

  Shape {
    width: 36
    height: 36
    scale: root.iconSize / 36
    transformOrigin: Item.TopLeft
    opacity: root.iconOpacity
    antialiasing: true
    preferredRendererType: Shape.CurveRenderer

    ShapePath {
      fillColor: root.color
      fillRule: ShapePath.OddEvenFill
      strokeWidth: -1
      strokeColor: "transparent"
      PathSvg { path: "M18 2 L31 7 V17 C31 25.5 25.6 31.6 18 34 C10.4 31.6 5 25.5 5 17 V7 Z" }
      PathSvg { path: "M18 11 A4 4 0 0 0 16.2 18.6 L15 25 H21 L19.8 18.6 A4 4 0 0 0 18 11 Z" }
    }
  }
}
```

- [ ] **Step 3: Port `Service.qml`**

Copy the reference `Service.qml`, then:

1. Comment line 1 of the header: `// Runs bin/enteauth-list. Each run returns a window of upcoming codes per`
2. `return base + "bin/enteauth-list"` (in `helperPath`) and `!helperPath.endsWith("/bin/enteauth-list")` (in `_run`).
3. Comment above `check()`: `// Health only (deps, database, keyring) for the bar icon; returns no codes.`
4. Add below `property var error: null`: `property int skipped: 0`
5. In `forget()`, add `skipped = 0`.
6. In `apply()`, inside `if (_wantCodes) {`, add as the first line: `skipped = Number(parsed.skipped) || 0`
7. Backstop timer comment: `// Backstop for a helper that hangs anyway: SIGTERM, which the helper turns into a clean exit.`

- [ ] **Step 4: Port `Panel.qml`**

Copy the reference `Panel.qml`, then make these edits (line numbers refer to the reference file):

1. Lines 10–20 header comment: first line becomes `// Ente Auth codes in the bar. Clicking the icon opens a`; in the keys table replace `Tab/Shift+Tab      next panel   Ctrl+P       pin / unpin` with `Tab/Shift+Tab      next panel   Esc          close` and delete the following `//   Esc                close` line.
2. Lines 24–25: `moduleName: "lcd1232.ente-auth"` and `ipcTarget: "lcd1232.ente-auth"`.
3. Line 55: `return base + "bin/enteauth-clipcheck"`; line 246: `if (!clipcheckPath.endsWith("/bin/enteauth-clipcheck")) return`.
4. Line 67: `return (v === "alpha" || v === "ente") ? v : "recent"`.
5. Lines 81–84 comment: `// ---------- Recent use ----------` / `// Stored as entry keys (Ente ids) only, never codes or seeds. All file` (keep the rest of that comment, with `bin/enteauth-prefs`).
6. Delete line 86 `property var pins: ({})`.
7. Lines 93, 97, 104: `bin/protonauth-prefs` → `bin/enteauth-prefs`.
8. In `prefsRead` (lines 124, 127): delete both `root.pins = ...` lines.
9. Line 140: `write(JSON.stringify({ used: root.used }) + "\n")`.
10. Delete `function togglePin(entry) { ... }` (lines 149–157).
11. Line 169: `readonly property var rows: Model.rankEntries(svc.entries, searchText, used, sortMode)`.
12. Replace the `statusLine` property (lines 173–178) with:

```qml
  readonly property string statusLine: Model.statusHint({
    refreshing: svc.refreshing, ok: svc.ok, error: svc.error, total: svc.entries.length,
    shown: rows.length, query: searchText, skipped: svc.skipped
  })
```

13. Delete `function openApp() { ... }` (lines 254–265).
14. Line 386: `ProtonAuthIcon {` → `EnteAuthIcon {`.
15. Line 419: `acceptedButtons: Qt.LeftButton`; lines 422–426 `onClicked` becomes:

```qml
      onClicked: {
        root.selectedIndex = row.index
        root.copyCode(row.entry, row.st.code, false)
      }
```

16. Line 448 comment: `// Labels come from Ente data and are untrusted: never render them as rich text.`
17. Lines 552–553: delete the `} else if (ctrl && event.key === Qt.Key_P) {` branch and its body line.
18. Line 613–616 `fixed`: remove `+ separatorB.height` and `+ openButton.height`, and change `column.spacing * 6` to `column.spacing * 4` (two fewer children in `column`).
19. Line 667: `text: "↵ copy   ⇧↵ next"`.
20. Delete the `PanelSeparator { id: separatorB; ... }` line just above the button and the whole `Button { id: openButton ... }` block (lines 676–689).

Then run:

```bash
grep -n -i "proton\|protonauth\|togglePin\|openApp\|openButton\|separatorB\|pins\b\|vault" Panel.qml Service.qml
```

Expected: no output. (`row.modelData.pinned` stays; it's `pinned`, not `pins`.)

- [ ] **Step 5: Validate the plugin**

Run: `omarchy plugin validate "$PWD"`
Expected: validation passes. Fix any reported manifest errors and re-run.

- [ ] **Step 6: Install locally and verify by hand**

```bash
ln -sfn "$PWD" ~/.config/omarchy/plugins/lcd1232.ente-auth
omarchy plugin list | grep lcd1232.ente-auth
```

If the plugin isn't listed (symlinks not followed), replace the link with a copy: `rm ~/.config/omarchy/plugins/lcd1232.ente-auth && cp -r "$PWD" ~/.config/omarchy/plugins/lcd1232.ente-auth` (repeat the copy after each change).

```bash
omarchy plugin enable lcd1232.ente-auth
omarchy restart shell
```

Check each of these, and note the result:
- [ ] Bar icon (shield) appears; click opens the panel with the search field focused.
- [ ] All non-trashed accounts are listed (real data: 28 = 31 rows − 3 trashed).
- [ ] Typing filters; Enter copies the top match; `wl-paste` shows the right code (compare with the Ente Auth app).
- [ ] Shift+Enter copies the next code; footer shows `↵ copy   ⇧↵ next`, no `^P pin`, no "Add in …" button.
- [ ] Pin an account in the Ente Auth app, reopen Ente Auth once (so it writes the DB), right-click the bar icon: that account is first, with the pin glyph.
- [ ] Right-click on a row does nothing; Ctrl+P does nothing.
- [ ] After 20 s the clipboard is cleared.
- [ ] `omarchy bar set lcd1232.ente-auth sortMode ente` → order matches the Ente app.
- [ ] `omarchy bar set lcd1232.ente-auth demoMode true` → demo accounts; set back to `false`.
- [ ] Lock the keyring (`busctl --user call org.freedesktop.secrets /org/freedesktop/secrets org.freedesktop.Secret.Service Lock ao 1 /org/freedesktop/secrets/collection/login`), reopen panel → keyring message or unlock prompt; unlock afterwards.

- [ ] **Step 7: Add the manifest check to CI**

Append to `.github/workflows/ci.yml`:

```yaml
      - name: Manifest is valid JSON
        run: python -m json.tool manifest.json > /dev/null
```

- [ ] **Step 8: Commit**

```bash
git add manifest.json Service.qml Panel.qml EnteAuthIcon.qml assets/icon.svg .github/workflows/ci.yml
git commit -m "feat: Ente Auth bar panel ported from omarchy-proton-authenticator"
```

---

### Task 10: README, license credit, real-data check

**Files:**
- Create: `README.md`
- Modify: `LICENSE`

- [ ] **Step 1: Real-data check (counts only)**

Run: `bin/enteauth-list --check`
Expected (this machine, 2026-10-11): `{"ok":true,...,"entries":[],"error":null,"check":{"entries":28,"skipped":0}}`. If `skipped` > 0 or the code is not 0, stop and debug with superpowers:systematic-debugging before continuing.

- [ ] **Step 2: Credit the reference in `LICENSE`**

Append to `LICENSE`:

```text

---

Panel.qml, Service.qml, Model.js, bin/enteauth-prefs and bin/enteauth-clipcheck
are derived from omarchy-proton-authenticator
(https://github.com/navjottomer/omarchy-proton-authenticator), MIT License,
Copyright (c) 2026 mapski.
```

- [ ] **Step 3: Write `README.md`**

````markdown
# Omarchy Ente Auth

Your [Ente Auth](https://ente.io/auth) 2FA codes in the Omarchy bar. Open the
panel, type a few letters, press Enter: the code is on your clipboard. No app
window, no network.

## Features

- **Launcher-style search.** The search field has focus as soon as the panel
  opens; Enter copies the top match.
- **Ente pins and recent first.** Accounts you pinned in Ente Auth come first;
  the rest are ordered by when you last copied them here.
- **Next code too.** Shift+Enter copies the code for the next period.
- **Follows your theme.** Built from the stock Omarchy panel parts.
- **Clipboard hygiene.** Codes are copied with `--sensitive` and cleared after
  20 seconds if they are still on the clipboard.
- **No extra dependencies.** Python stdlib and libsodium, both already on
  Omarchy.

## Requirements

- [Omarchy](https://omarchy.org) with the Quickshell-based Omarchy shell
- Ente Auth desktop (`ente-auth-bin` on the AUR), signed in (or in offline
  mode) and opened at least once on this machine
- `libsodium`, `libsecret`, `wl-clipboard`, `libnotify`

```sh
omarchy pkg add libsodium libsecret wl-clipboard libnotify
omarchy pkg aur add ente-auth-bin
```

## Install

```sh
omarchy plugin add https://github.com/lcd1232/omarchy-totp.git --enable
```

Optional hotkey, in `~/.config/hypr/bindings.lua`:

```lua
o.bind("SUPER + CTRL + U", "Ente Auth", "omarchy-shell shell toggle lcd1232.ente-auth")
```

Update with `omarchy plugin update lcd1232.ente-auth`; remove with
`omarchy plugin remove lcd1232.ente-auth` and delete
`~/.local/state/lcd1232.ente-auth/` (last-used times).

## Usage

| Key | Action |
|---|---|
| type | filter accounts |
| Enter | copy the current code |
| Shift+Enter | copy the next code |
| Up/Down, Ctrl+J/K, PgUp/PgDn | move the selection |
| Tab / Shift+Tab | switch to the next bar panel |
| Esc | close |

Click a row to copy its code. Right-click the bar icon to reload. To pin an
account, pin it in Ente Auth.

From scripts: `omarchy-shell lcd1232.ente-auth toggle` (also `open`, `close`,
`refresh`, `clearClipboard`).

## Settings

`omarchy bar set lcd1232.ente-auth <key> <value>`:

| Key | Default | Meaning |
|---|---|---|
| `sortMode` | `recent` | after Ente-pinned accounts: `recent` (last copied first, then A–Z), `alpha`, or `ente` (Ente Auth's order) |
| `closeOnCopy` | `true` | close the panel after copying |
| `notifyOnCopy` | `true` | show a notification naming the copied account |
| `clipboardClearSec` | `20` | seconds before a copied code is cleared (`0` = never) |
| `demoMode` | `false` | fake accounts, for screenshots; never reads your data |

## How it works

The panel runs `bin/enteauth-list`, a small stdlib-only Python helper that:

1. opens Ente Auth's local database
   (`~/.local/share/io.ente.auth/.ente.authenticator.db`) read-only,
2. reads Ente Auth's key from the Secret Service keyring with `secret-tool`,
3. decrypts each entry in memory with libsodium (XChaCha20-Poly1305
   secretstream, the same format Ente uses for sync),
4. drops trashed entries and prints labels plus the next 10 codes per account
   as JSON.

The panel picks the current code from its own clock and runs the helper again
about every five minutes while open.

New accounts added on another device appear after Ente Auth desktop has synced
them, which it does each time it starts.

## Privacy and security

- **No network.** Nothing is sent anywhere.
- **Secrets stay in the helper.** TOTP secrets never leave the short-lived
  helper process; the shell only holds labels and codes.
- **Nothing decrypted touches the disk.** The database is opened read-only.
- **Codes never on a command line.** Codes go to `wl-copy` on stdin.
- **Stored data.** Only last-used times, in
  `~/.local/state/lcd1232.ente-auth/prefs.json` (private folder, no symlinks).

Like every Omarchy plugin, this runs as unsandboxed code in your shell. Review
it before installing.

## Troubleshooting

| Message | Fix |
|---|---|
| Ente Auth data not found | install Ente Auth, open it and sign in once |
| Not signed in to Ente Auth | sign in to Ente Auth (or choose offline mode) |
| Keyring is locked | unlock your login keyring and reopen the panel |
| Ente Auth is busy | retry; Ente Auth was writing its database |
| N entries could not be read | open Ente Auth so it re-syncs; report if it persists |
| Missing dependency | install the packages under [Requirements](#requirements) |

Check the setup without showing codes: `bin/enteauth-list --check`.

## Development

```sh
python3 -m unittest discover -s tests -v
node --test tests/model.test.mjs
```

## Credits

Panel, model and helpers are derived from
[omarchy-proton-authenticator](https://github.com/navjottomer/omarchy-proton-authenticator)
(MIT). See `LICENSE`.
````

- [ ] **Step 4: Run the full suite**

```bash
python3 -m unittest discover -s tests -v
node --test tests/model.test.mjs
```

Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add README.md LICENSE
git commit -m "docs: README and license credit"
```
