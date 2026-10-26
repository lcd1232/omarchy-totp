#!/usr/bin/env python3
"""Emit Ente Auth TOTP codes from the desktop app's local DB (labels + codes only).

Reads Ente Auth's encrypted SQLite DB read-only, takes the key from the Secret
Service keyring, decrypts each entry in memory with libsodium and prints a
window of upcoming codes per entry as one JSON line. Secrets never leave this
process."""
from __future__ import annotations

import argparse
import base64
import binascii
import ctypes
import ctypes.util
import hashlib
import hmac
import json
import os
import re
import shutil
import signal
import sqlite3
import struct
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

__version__ = "1.0.2"

DATA_DIR = Path.home() / ".local/share/io.ente.auth"
ONLINE_DB = ".ente.authenticator.db"
OFFLINE_DB = ".ente.offline_authenticator.db"
KEYRING_ACCOUNT = "io.ente.auth.secureStorage"
ENTE_APP = "/usr/bin/enteauth"                # from the ente-auth-bin package
INSTALL_APP = "omarchy pkg aur add ente-auth-bin"
# Icons bundled with the Ente Auth desktop app: its own set plus Simple Icons.
ICON_ROOT = Path("/usr/share/enteauth/data/flutter_assets/assets")
HEX_COLOR_RE = re.compile(r"^[0-9A-Fa-f]{6}$")
# Ente's charMap (icon_utils.dart) for Simple Icons file names without a slug.
SIMPLE_ICON_CHAR_MAP = {
    "á": "a", "à": "a", "â": "a", "ä": "a", "ã": "a", "é": "e", "è": "e", "ê": "e", "ë": "e",
    "í": "i", "ì": "i", "î": "i", "ï": "i", "ó": "o", "ò": "o", "ô": "o", "ö": "o",
    "ú": "u", "ù": "u", "û": "u", "ü": "u", "ç": "c", "ñ": "n", "ř": "r", "š": "s", "ż": "z",
    ".": "dot", "-": "", "&": "and", "+": "plus", ":": "", "/": "", "!": "", "_": "", "°": "", "'": "",
}
# Absolute path first so a PATH entry can't substitute the keyring client.
SECRET_TOOL = "/usr/bin/secret-tool" if os.path.exists("/usr/bin/secret-tool") else "secret-tool"
SECRET_TOOL_TIMEOUT_SEC = 10   # a keyring unlock prompt left open, etc.
KEYRING_MAX_BYTES = 64 * 1024  # flutter_secure_storage JSON; a few hundred bytes in practice
MAX_ENTRIES = 1000
MAX_LABEL_CHARS = 256          # issuer / account, truncated for display
MAX_ID_CHARS = 128
DB_BUSY_RETRY_SEC = 0.2
HELPER_TIMEOUT_SEC = 20        # whole run; SIGALRM -> HELPER_TIMEOUT JSON
MAX_MESSAGE_CHARS = 200
MAX_OUTPUT_BYTES = 1024 * 1024 # omarchy-shell buffers our whole stdout
DEFAULT_WINDOW = 10
MAX_WINDOW = 20

# libsodium secretstream tags (crypto_secretstream_xchacha20poly1305_TAG_*).
TAG_MESSAGE = 0
TAG_FINAL = 3


class Err(Exception):
    """Fatal error, reported to the panel as {"error": {"code", "message"}}."""

    def __init__(self, code: str, message: str, install: str = ""):
        super().__init__(message)
        self.code = code
        self.message = message
        self.install = install  # shell command that fixes it, shown with a Copy button


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


def _int_param(q: dict, name: str, default: int, lo: int, hi: int) -> int:
    raw = q.get(name)
    if raw in (None, ""):
        return default
    value = int(raw)  # ValueError for non-numbers
    if not lo <= value <= hi:
        raise ValueError(f"{name} out of range")
    return value


def _display_int(display: dict, name: str) -> int:
    value = display.get(name)
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _display_str(display: dict, name: str) -> str:
    value = display.get(name)
    return value if isinstance(value, str) else ""


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
    position = _display_int(display, "position")
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
        "lastUsedAt": max(0, _display_int(display, "lastUsedAt")),
        "iconSrc": _display_str(display, "iconSrc"),
        "iconID": _display_str(display, "iconID"),
    }


def _secret_tool(secret_tool: str, command: str) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(  # fixed argv, no shell
            [secret_tool, command, "account", KEYRING_ACCOUNT],
            stdin=subprocess.DEVNULL, capture_output=True, timeout=SECRET_TOOL_TIMEOUT_SEC, check=False,
        )
    except FileNotFoundError as e:
        raise Err("DEPS_MISSING", "secret-tool not found (install package: libsecret)") from e
    except subprocess.TimeoutExpired as e:
        raise Err("HELPER_TIMEOUT", "secret-tool did not answer (keyring prompt open?)") from e


def read_keys(secret_tool: str = SECRET_TOOL) -> dict:
    """Ente Auth's flutter_secure_storage values from the Secret Service."""
    proc = _secret_tool(secret_tool, "lookup")
    out = proc.stdout
    if len(out) > KEYRING_MAX_BYTES:
        raise Err("UNSUPPORTED_SCHEMA", "keyring item too large")
    if proc.returncode != 0:
        if proc.stderr.strip():  # no Secret Service, D-Bus error, ...
            raise Err("KEYRING_LOCKED", "Secret Service unavailable — unlock the login keyring")
        # lookup also fails silently for a locked item; search (without
        # --unlock) still lists a locked item's attributes. Its output is
        # only checked for emptiness, never kept.
        if _secret_tool(secret_tool, "search").stdout.strip():
            raise Err("KEYRING_LOCKED", "Ente Auth's keyring item is locked — unlock the login keyring")
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


def _icon_key(name: str) -> str:
    return name.replace(" ", "").lower()


def _icon_entries(path: Path) -> list:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    icons = data.get("icons") if isinstance(data, dict) else data
    return [i for i in icons if isinstance(i, dict)] if isinstance(icons, list) else []


def load_icon_index(root: Path) -> tuple[dict, dict]:
    """Ente Auth's icon lookup tables: (custom, simple), key -> (relative path, hex).

    Keys and file names follow Ente's IconUtils: title without spaces, lower case.
    A missing or broken index just means no icons.
    """
    custom: dict = {}
    for icon in _icon_entries(root / "custom-icons/_data/custom-icons.json"):
        title, slug = icon.get("title"), icon.get("slug")
        if not isinstance(title, str):
            continue
        key = _icon_key(title)
        entry = (f"custom-icons/icons/{slug if isinstance(slug, str) else key}.svg", icon.get("hex"))
        custom[key] = entry
        alt_names = icon.get("altNames")
        for alt in alt_names if isinstance(alt_names, list) else []:
            if isinstance(alt, str):
                custom[_icon_key(alt)] = entry
    simple: dict = {}
    for icon in _icon_entries(root / "simple-icons/_data/simple-icons.json"):
        title, slug = icon.get("title"), icon.get("slug")
        if not isinstance(title, str):
            continue
        key = _icon_key(title)
        stem = slug if isinstance(slug, str) else "".join(
            SIMPLE_ICON_CHAR_MAP.get(c, c) for c in key).strip()
        simple[key] = (f"simple-icons/icons/{stem}.svg", icon.get("hex"))
    return custom, simple


def resolve_icon(name: str, index: tuple[dict, dict], root: Path) -> tuple[str, str]:
    """(absolute .svg path, RRGGBB colour or "") for an issuer or icon id, like Ente Auth.

    Ente's own icons win over Simple Icons; "Google (work)" and "google.com" fall
    back to the part before the bracket or dot. Only files inside `root` count.
    """
    title = _icon_key(name)
    if not title:
        return "", ""
    candidates = [title] + [title.split(c)[0] for c in "(." if c in title]
    for candidate in candidates:
        for table in index:
            if candidate not in table:
                continue
            rel, color = table[candidate]
            try:
                base = root.resolve()
                path = (root / rel).resolve()
            except OSError:
                return "", ""
            if path.suffix != ".svg" or not path.is_relative_to(base) or not path.is_file():
                return "", ""
            ok = isinstance(color, str) and HEX_COLOR_RE.match(color)
            return str(path), color.upper() if ok else ""
    return "", ""


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


def _entry_icon(otp: dict, icons: tuple[dict, dict]) -> dict:
    # An icon picked in Ente Auth wins over the one matching the issuer.
    name = otp["iconID"] if otp["iconSrc"] and otp["iconID"] else otp["issuer"]
    path, color = resolve_icon(name, icons, ICON_ROOT)
    return {"icon": path, "iconColor": color}


def list_entries(window: int, now: int | None = None, data_dir: Path | None = None,
                 keys: dict | None = None) -> dict:
    data_dir = DATA_DIR if data_dir is None else data_dir
    now = int(time.time()) if now is None else now
    # Before touching the keyring: no DB means Ente Auth was never set up here.
    if not any((data_dir / name).is_file() for name in (ONLINE_DB, OFFLINE_DB)):
        if not os.path.exists(ENTE_APP):
            raise Err("APP_MISSING", "Ente Auth is not installed", install=INSTALL_APP)
        raise Err("DB_MISSING", f"no Ente Auth database in {data_dir}")
    db_path, key = select_vault(read_keys() if keys is None else keys, data_dir)
    rows = load_rows(db_path)
    if len(rows) > MAX_ENTRIES:
        raise Err("OUTPUT_TOO_LARGE", f"more than {MAX_ENTRIES} entries")
    entries: list[dict] = []
    skipped = 0
    icons = load_icon_index(ICON_ROOT) if rows else ({}, {})
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
            "lastUsedAt": otp["lastUsedAt"],
            **_entry_icon(otp, icons),
            **code_window(seed, otp["digits"], otp["algorithm"], otp["period"], now, window),
        })
    if rows and skipped == len(rows):
        raise Err("DECRYPT_FAILED", "no entry could be decrypted (wrong key?)")
    return {"ok": True, "updatedAt": iso_time(now), "entries": entries, "skipped": skipped, "error": None}


def fail(code: str, message: str, install: str = "") -> dict:
    error = {"code": code, "message": str(message)[:MAX_MESSAGE_CHARS]}
    if install:
        error["install"] = install
    return {"ok": False, "updatedAt": iso_time(int(time.time())), "entries": [], "error": error}


def missing_packages() -> list[str]:
    """Packages the plugin needs at runtime that are not installed."""
    checks = [
        ("libsodium", lambda: ctypes.util.find_library("sodium")),
        ("libsecret", lambda: shutil.which("secret-tool")),
        ("wl-clipboard", lambda: shutil.which("wl-copy")),
        # libnotify is not checked: without notify-send only the "copied"
        # notification is missing, the codes still work.
    ]
    return [package for package, present in checks if not present()]


def require_packages() -> None:
    missing = missing_packages()
    if missing:
        raise Err("DEPS_MISSING", "missing packages: " + ", ".join(missing),
                  install="omarchy pkg add " + " ".join(missing))


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
DEMO_ACCOUNTS = [  # issuer, account, seed, digits, pinned, last used (minutes ago, 0 = never)
    ("GitHub", "octocat@example.com", "JBSWY3DPEHPK3PXP", 6, True, 0),
    ("Ente", "demo@ente.io", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 6, False, 0),
    ("Google", "jane.doe@example.com", "KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ", 6, False, 5),
    ("AWS", "root@example.org", "MFRGGZDFMZTWQ2LKNNWG23TPOBYXE43U", 6, False, 0),
    ("Discord", "jane#0001", "ONSWG4TFORZWK3DUMVZXG5DFON2A", 6, False, 90),
    ("Tailscale", "jane@example.net", "OBQXG43XN5ZGIZLYMFWXA3DF", 8, False, 0),
]


def demo(window: int, now: int | None = None) -> dict:
    now = int(time.time()) if now is None else now
    entries = []
    icons = load_icon_index(ICON_ROOT)
    for i, (issuer, account, seed, digits, pinned, minutes_ago) in enumerate(DEMO_ACCOUNTS):
        entries.append({
            "id": f"demo-{i}", "issuer": issuer, "account": account, "period": 30,
            "digits": digits, "pinned": pinned, "position": i,
            # Ente stores lastUsedAt in microseconds.
            "lastUsedAt": (now - minutes_ago * 60) * 1_000_000 if minutes_ago else 0,
            **dict(zip(("icon", "iconColor"), resolve_icon(issuer, icons, ICON_ROOT))),
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
        require_packages()
        if args.check:
            emit(check())
            return 0
        payload = list_entries(window)
        if any("secret" in e for e in payload["entries"]):
            raise Err("DECRYPT_FAILED", "refusing to emit secret field")
        emit(payload)
        return 0
    except Err as e:
        emit(fail(e.code, e.message, e.install))
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
