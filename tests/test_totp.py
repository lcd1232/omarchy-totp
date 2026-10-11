import unittest

from support import ea

# RFC 6238 appendix B seeds and vectors (8 digits, 30 s period).
SEEDS = {
    "SHA1": b"12345678901234567890",
    "SHA256": b"12345678901234567890123456789012",
    "SHA512": b"1234567890" * 6 + b"1234",
}
VECTORS = [
    (59, "94287082", "46119246", "90693936"),
    (1111111109, "07081804", "68084774", "25091201"),
    (1111111111, "14050471", "67062674", "99943326"),
    (1234567890, "89005924", "91819424", "93441116"),
    (2000000000, "69279037", "90698825", "38618901"),
    (20000000000, "65353130", "77737706", "47863826"),
]
# RFC 4226 appendix D (6 digits, counters 0..9).
HOTP_SHA1 = ["755224", "287082", "359152", "969429", "338314",
             "254676", "287922", "162583", "399871", "520489"]


class TotpTest(unittest.TestCase):
    def test_rfc6238_vectors(self):
        for t, *expected in VECTORS:
            for alg, want in zip(("SHA1", "SHA256", "SHA512"), expected):
                with self.subTest(t=t, alg=alg):
                    self.assertEqual(ea.hotp(SEEDS[alg], t // 30, 8, alg), want)

    def test_rfc4226_vectors(self):
        self.assertEqual([ea.hotp(SEEDS["SHA1"], c, 6, "SHA1") for c in range(10)], HOTP_SHA1)

    def test_code_window(self):
        w = ea.code_window(SEEDS["SHA1"], 6, "SHA1", 30, 59, 3)
        self.assertEqual(w, {"counter": 1, "codes": ["287082", "359152", "969429"]})

    def test_b32_decode(self):
        self.assertEqual(ea.b32decode_secret("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"), SEEDS["SHA1"])

    def test_b32_secret_normalisation(self):
        # Review Focus 2: lowercase, spaces, dashes, missing padding.
        self.assertEqual(ea.b32decode_secret("gezd gnbv gy3t qojq-gezd gnbv gy3t qojq"), SEEDS["SHA1"])
        self.assertEqual(ea.b32decode_secret("JBSWY3DPEHPK3PX"), ea.b32decode_secret("JBSWY3DPEHPK3PX="))

    def test_b32_invalid(self):
        for bad in ("", "!!!!", "18"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                ea.b32decode_secret(bad)


if __name__ == "__main__":
    unittest.main()
