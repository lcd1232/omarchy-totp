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
