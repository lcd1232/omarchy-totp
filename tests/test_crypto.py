import unittest

from support import ea, secretstream_encrypt

KEY = bytes(range(32))


class SecretstreamDecryptTest(unittest.TestCase):
    def test_round_trip_final_tag(self):
        header, ct = secretstream_encrypt(KEY, b'"otpauth://totp/x?secret=AA"', ea.TAG_FINAL)
        self.assertEqual(ea.secretstream_decrypt(KEY, header, ct), b'"otpauth://totp/x?secret=AA"')

    def test_round_trip_message_tag(self):
        # Real Ente data has rows with TAG_MESSAGE as well as TAG_FINAL.
        header, ct = secretstream_encrypt(KEY, b"hello", ea.TAG_MESSAGE)
        self.assertEqual(ea.secretstream_decrypt(KEY, header, ct), b"hello")

    def test_empty_plaintext(self):
        header, ct = secretstream_encrypt(KEY, b"")
        self.assertEqual(ea.secretstream_decrypt(KEY, header, ct), b"")

    def test_wrong_key_fails(self):
        header, ct = secretstream_encrypt(KEY, b"hello")
        with self.assertRaises(ea.DecryptError):
            ea.secretstream_decrypt(bytes(32), header, ct)

    def test_tampered_ciphertext_fails(self):
        header, ct = secretstream_encrypt(KEY, b"hello")
        bad = ct[:-1] + bytes([ct[-1] ^ 1])
        with self.assertRaises(ea.DecryptError):
            ea.secretstream_decrypt(KEY, header, bad)

    def test_bad_lengths_fail(self):
        header, ct = secretstream_encrypt(KEY, b"hello")
        for key, hdr, data in ((KEY[:31], header, ct), (KEY, header[:23], ct), (KEY, header, ct[:16])):
            with self.assertRaises(ea.DecryptError):
                ea.secretstream_decrypt(key, hdr, data)


if __name__ == "__main__":
    unittest.main()
