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
