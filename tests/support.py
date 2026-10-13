"""Shared test helpers: import the helper from bin/ and build fixture data."""
from __future__ import annotations

import base64
import ctypes
import json
import sqlite3
import sys
from pathlib import Path
from urllib.parse import quote, urlencode

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
