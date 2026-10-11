import json
import unittest
from urllib.parse import quote

from support import ea


def cd(**fields) -> str:
    return quote(json.dumps(fields))


class ParseOtpauthTest(unittest.TestCase):
    def test_full_uri(self):
        uri = ("otpauth://totp/GitHub:me@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
               "&algorithm=sha256&digits=8&period=60"
               f"&codeDisplay={cd(pinned=True, trashed=False, position=4, tags=[], note='')}")
        self.assertEqual(ea.parse_otpauth(uri), {
            "issuer": "GitHub", "account": "me@example.com", "secret": "JBSWY3DPEHPK3PXP",
            "digits": 8, "period": 60, "algorithm": "SHA256",
            "pinned": True, "trashed": False, "position": 4,
        })

    def test_defaults(self):
        p = ea.parse_otpauth("otpauth://totp/acct?secret=JBSWY3DPEHPK3PXP")
        self.assertEqual((p["digits"], p["period"], p["algorithm"]), (6, 30, "SHA1"))
        self.assertEqual((p["pinned"], p["trashed"], p["position"]), (False, False, 0))

    def test_label_variants(self):
        # Review Focus 3.
        cases = {
            "otpauth://totp/me@example.com?secret=AA": ("", "me@example.com"),
            "otpauth://totp/me@example.com?secret=AA&issuer=Proton": ("Proton", "me@example.com"),
            "otpauth://totp/ACME%20Co%3Ajane%40acme.io?secret=AA": ("ACME Co", "jane@acme.io"),
            "otpauth://totp/Label%3Auser?secret=AA&issuer=Param": ("Param", "user"),
            "otpauth://totp/%D0%AF%D0%BD%D0%B4%D0%B5%D0%BA%D1%81:%C3%BCser?secret=AA": ("Яндекс", "üser"),
            "otpauth://totp/Issuer:%20spaced%20?secret=AA": ("Issuer", "spaced"),
        }
        for uri, (issuer, account) in cases.items():
            with self.subTest(uri=uri):
                p = ea.parse_otpauth(uri)
                self.assertEqual((p["issuer"], p["account"]), (issuer, account))

    def test_trashed(self):
        p = ea.parse_otpauth(f"otpauth://totp/x?secret=AA&codeDisplay={cd(trashed=True)}")
        self.assertTrue(p["trashed"])

    def test_code_display_missing_or_malformed(self):
        # Review Focus 5: still listed, unpinned, position 0.
        for tail in ("", "&codeDisplay=", "&codeDisplay=%7Bnot-json", "&codeDisplay=%5B1%2C2%5D",
                     f"&codeDisplay={cd(pinned='yes', position='3')}"):
            with self.subTest(tail=tail):
                p = ea.parse_otpauth("otpauth://totp/x?secret=AA" + tail)
                self.assertEqual((p["pinned"], p["trashed"], p["position"]), (False, False, 0))

    def test_non_totp_is_none(self):
        self.assertIsNone(ea.parse_otpauth("otpauth://hotp/x?secret=AA&counter=1"))
        self.assertIsNone(ea.parse_otpauth("otpauth://steam/x?secret=AA"))

    def test_invalid(self):
        for uri in ("https://example.com", "otpauth://totp/x", "otpauth://totp/x?secret=",
                    "otpauth://totp/x?secret=AA&digits=0", "otpauth://totp/x?secret=AA&digits=11",
                    "otpauth://totp/x?secret=AA&digits=six", "otpauth://totp/x?secret=AA&period=0",
                    "otpauth://totp/x?secret=AA&algorithm=MD5"):
            with self.subTest(uri=uri), self.assertRaises(ValueError):
                ea.parse_otpauth(uri)


if __name__ == "__main__":
    unittest.main()
