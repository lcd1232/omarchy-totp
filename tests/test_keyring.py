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
