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
