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
import struct

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
