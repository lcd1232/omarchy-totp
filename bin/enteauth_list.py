#!/usr/bin/env python3
"""Emit Ente Auth TOTP codes from the desktop app's local DB (labels + codes only).

Reads Ente Auth's encrypted SQLite DB read-only, takes the key from the Secret
Service keyring, decrypts each entry in memory with libsodium and prints a
window of upcoming codes per entry as one JSON line. Secrets never leave this
process."""
from __future__ import annotations

import base64
import binascii
import ctypes
import ctypes.util
import hashlib
import hmac
import json
import os
import struct
import subprocess
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

__version__ = "1.0.0"

DATA_DIR = Path.home() / ".local/share/io.ente.auth"
ONLINE_DB = ".ente.authenticator.db"
OFFLINE_DB = ".ente.offline_authenticator.db"
KEYRING_ACCOUNT = "io.ente.auth.secureStorage"
# Absolute path first so a PATH entry can't substitute the keyring client.
SECRET_TOOL = "/usr/bin/secret-tool" if os.path.exists("/usr/bin/secret-tool") else "secret-tool"
SECRET_TOOL_TIMEOUT_SEC = 10   # a keyring unlock prompt left open, etc.
KEYRING_MAX_BYTES = 64 * 1024  # flutter_secure_storage JSON; a few hundred bytes in practice

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
