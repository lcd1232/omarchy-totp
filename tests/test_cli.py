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
                   mock.patch.object(ea, "missing_packages", return_value=[]),
                   mock.patch.object(ea, "ICON_ROOT", self.dir / "no-icons"),
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

    def test_missing_packages_give_one_install_command(self):
        with mock.patch.object(ea, "missing_packages", return_value=["libsodium", "wl-clipboard"]), \
             mock.patch.object(ea, "list_entries", side_effect=AssertionError("vault read")):
            for args in ((), ("--check",)):
                rc, out = run_main(*args)
                self.assertEqual(rc, 1)
                self.assertEqual(out["error"]["code"], "DEPS_MISSING")
                self.assertEqual(out["error"]["install"], "omarchy pkg add libsodium wl-clipboard")

    def test_install_command_reaches_json(self):
        err = ea.Err("APP_MISSING", "Ente Auth is not installed", install="omarchy pkg aur add ente-auth-bin")
        with mock.patch.object(ea, "list_entries", side_effect=err):
            rc, out = run_main()
        self.assertEqual(out["error"]["install"], "omarchy pkg aur add ente-auth-bin")

    def test_errors_without_install_have_no_install_field(self):
        with mock.patch.object(ea, "read_keys", side_effect=ea.Err("NOT_SIGNED_IN", "no")):
            rc, out = run_main()
        self.assertNotIn("install", out["error"])

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
        self.assertTrue(all("icon" in e and "iconColor" in e for e in out["entries"]))
        # Some recently used, some never: shows the recent-first ordering.
        used = [e["lastUsedAt"] for e in out["entries"]]
        self.assertTrue(any(used) and not all(used))


class MissingPackagesTest(unittest.TestCase):
    def test_reports_each_missing_package_once(self):
        present = {"secret-tool", "wl-copy"}
        with mock.patch.object(ea.shutil, "which", side_effect=lambda n: f"/usr/bin/{n}" if n in present else None), \
             mock.patch.object(ea.ctypes.util, "find_library", return_value=None):
            self.assertEqual(ea.missing_packages(), ["libsodium", "wl-clipboard", "libnotify"])

    def test_nothing_missing(self):
        with mock.patch.object(ea.shutil, "which", side_effect=lambda n: f"/usr/bin/{n}"), \
             mock.patch.object(ea.ctypes.util, "find_library", return_value="libsodium.so.26"):
            self.assertEqual(ea.missing_packages(), [])


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
