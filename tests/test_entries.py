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
            ("ent-1", *encrypt_row(otpauth(code_display={"pinned": True, "position": 2, "lastUsedAt": 42}))),
            (None, *encrypt_row(otpauth("Acme:bob", issuer="Acme"), tag=ea.TAG_MESSAGE)),
        ])
        out = self.run_list()
        self.assertEqual((out["ok"], out["skipped"], out["error"]), (True, 0, None))
        self.assertEqual(out["updatedAt"], "1970-01-01T00:00:59Z")
        self.assertEqual(out["entries"][0], {
            "id": "ent-1", "issuer": "GitHub", "account": "me@example.com",
            "period": 30, "digits": 6, "pinned": True, "position": 2, "lastUsedAt": 42,
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
