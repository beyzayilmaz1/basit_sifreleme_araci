"""crypto_ops birim testleri — kendi algoritma yok; davranış sözleşmesi test edilir."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from sifreleme_araci.crypto_ops import (
    HEADER_LEN,
    MAGIC,
    MIN_BLOB_LEN,
    TAG_LEN,
    VERSION,
    AuthenticationError,
    CryptoError,
    FormatError,
    decrypt_bytes,
    describe_blob,
    encrypt_bytes,
    parse_envelope,
    verify_blob,
)


class EncryptDecryptTests(unittest.TestCase):
    def test_roundtrip_text(self) -> None:
        pw = "Dogru-Parola-2026!"
        pt = "gizli staj notu — şğüöç".encode("utf-8")
        blob = encrypt_bytes(pt, pw)
        self.assertEqual(decrypt_bytes(blob, pw), pt)

    def test_roundtrip_empty(self) -> None:
        pw = "bos-dosya"
        blob = encrypt_bytes(b"", pw)
        self.assertEqual(decrypt_bytes(blob, pw), b"")

    def test_roundtrip_binary(self) -> None:
        pw = "bin"
        pt = bytes(range(256)) + b"\x00\xff"
        self.assertEqual(decrypt_bytes(encrypt_bytes(pt, pw), pw), pt)

    def test_roundtrip_unicode_dense(self) -> None:
        pw = "ünîcode"
        pt = ("日本語 العربية עברית 🔐\n" * 20).encode("utf-8")
        self.assertEqual(decrypt_bytes(encrypt_bytes(pt, pw), pw), pt)

    def test_roundtrip_large_file(self) -> None:
        # ~1 MiB — bellek içi model; CI'da makul süre
        pw = "large"
        pt = os.urandom(1024 * 1024)
        self.assertEqual(decrypt_bytes(encrypt_bytes(pt, pw), pw), pt)

    def test_same_plaintext_different_ciphertext(self) -> None:
        pw = "ayni"
        pt = b"tekrar"
        a = encrypt_bytes(pt, pw)
        b = encrypt_bytes(pt, pw)
        self.assertNotEqual(a, b)  # taze salt + nonce

    def test_wrong_password(self) -> None:
        blob = encrypt_bytes(b"secret", "dogru")
        with self.assertRaises(AuthenticationError) as ctx:
            decrypt_bytes(blob, "yanlis")
        self.assertIn("Parola yanlış veya veri bozulmuş", str(ctx.exception))

    def test_wrong_password_message_does_not_distinguish(self) -> None:
        blob = encrypt_bytes(b"secret", "dogru")
        with self.assertRaises(AuthenticationError) as wrong_pw:
            decrypt_bytes(blob, "yanlis")
        tampered = bytearray(blob)
        tampered[-1] ^= 0xFF
        with self.assertRaises(AuthenticationError) as tampered_err:
            decrypt_bytes(bytes(tampered), "dogru")
        self.assertEqual(str(wrong_pw.exception), str(tampered_err.exception))

    def test_tampered_ciphertext(self) -> None:
        blob = bytearray(encrypt_bytes(b"secret", "pw"))
        blob[-1] ^= 0x01  # tag/ciphertext boz
        with self.assertRaises(AuthenticationError):
            decrypt_bytes(bytes(blob), "pw")

    def test_random_byte_corruption(self) -> None:
        blob = bytearray(encrypt_bytes(b"payload-data", "pw"))
        # Header sonrası rastgele bir baytı boz
        idx = HEADER_LEN + (len(blob) - HEADER_LEN) // 2
        blob[idx] ^= 0x5A
        with self.assertRaises(AuthenticationError):
            decrypt_bytes(bytes(blob), "pw")

    def test_invalid_version_rejected(self) -> None:
        # Desteklenmeyen sürüm auth'tan önce FormatError ile reddedilir.
        # AAD (MAGIC||VERSION) ek savunma katmanıdır (gelecek sürüm okuyucuları için).
        blob = bytearray(encrypt_bytes(b"secret", "pw"))
        blob[4] = 0x99
        with self.assertRaises(FormatError) as ctx:
            decrypt_bytes(bytes(blob), "pw")
        self.assertIn("sürüm", str(ctx.exception).lower())

    def test_tampered_salt_causes_auth_failure(self) -> None:
        # Salt AAD'de değil; yanlış salt → yanlış anahtar → AuthenticationError
        blob = bytearray(encrypt_bytes(b"secret", "pw"))
        blob[5] ^= 0x01
        with self.assertRaises(AuthenticationError):
            decrypt_bytes(bytes(blob), "pw")

    def test_bad_magic(self) -> None:
        blob = bytearray(encrypt_bytes(b"x", "pw"))
        blob[0:4] = b"XXXX"
        with self.assertRaises(FormatError) as ctx:
            decrypt_bytes(bytes(blob), "pw")
        # Beklenen MAGIC sabitini echo etmemeli
        self.assertNotIn(repr(MAGIC), str(ctx.exception))

    def test_invalid_header_too_short(self) -> None:
        with self.assertRaises(FormatError):
            decrypt_bytes(MAGIC + bytes([VERSION]) + b"\x00" * 10, "pw")

    def test_too_short(self) -> None:
        with self.assertRaises(FormatError):
            decrypt_bytes(MAGIC + b"\x01short", "pw")

    def test_empty_blob(self) -> None:
        with self.assertRaises(FormatError):
            decrypt_bytes(b"", "pw")

    def test_empty_password_rejected(self) -> None:
        with self.assertRaises(CryptoError):
            encrypt_bytes(b"x", "")

    def test_min_blob_len_constant(self) -> None:
        self.assertEqual(MIN_BLOB_LEN, HEADER_LEN + TAG_LEN)

    def test_inspect_metadata(self) -> None:
        blob = encrypt_bytes(b"abc", "pw")
        meta = describe_blob(blob)
        self.assertEqual(meta["magic"], "BSA1")
        self.assertEqual(meta["version"], 1)
        self.assertEqual(meta["cipher"], "AES-256-GCM")
        self.assertEqual(meta["tag_len"], TAG_LEN)
        self.assertGreater(meta["ciphertext_len"], 0)
        self.assertEqual(meta["approx_plaintext_len"], 3)

    def test_parse_envelope_version_field(self) -> None:
        blob = encrypt_bytes(b"z", "pw")
        env = parse_envelope(blob)
        self.assertEqual(env.version, VERSION)
        self.assertEqual(len(env.salt), 16)
        self.assertEqual(len(env.nonce), 12)

    def test_verify_blob_success(self) -> None:
        blob = encrypt_bytes(b"verify-me", "pw")
        self.assertTrue(verify_blob(blob, "pw"))

    def test_verify_blob_wrong_password(self) -> None:
        blob = encrypt_bytes(b"verify-me", "pw")
        with self.assertRaises(AuthenticationError):
            verify_blob(blob, "nope")

    def test_salt_nonce_not_in_plaintext_equality(self) -> None:
        """Aynı girdi farklı salt/nonce → ciphertext farklı, plaintext aynı."""
        a = encrypt_bytes(b"same", "pw")
        b = encrypt_bytes(b"same", "pw")
        self.assertNotEqual(a[5:5 + 16], b[5:5 + 16])  # salt
        self.assertEqual(decrypt_bytes(a, "pw"), decrypt_bytes(b, "pw"))

    def test_size_limit_rejects_oversized(self) -> None:
        from sifreleme_araci.crypto_ops import LimitError

        old = os.environ.get("BSA_MAX_BYTES")
        os.environ["BSA_MAX_BYTES"] = "4"
        try:
            with self.assertRaises(LimitError):
                encrypt_bytes(b"12345", "password-ok")
        finally:
            if old is None:
                os.environ.pop("BSA_MAX_BYTES", None)
            else:
                os.environ["BSA_MAX_BYTES"] = old

    def test_password_strength_soft_warn(self) -> None:
        from sifreleme_araci.crypto_ops import assess_password_strength

        self.assertIsNotNone(assess_password_strength("short"))
        self.assertIsNone(assess_password_strength("long-enough"))


class CliSmokeTests(unittest.TestCase):
    def test_version_flag(self) -> None:
        from sifreleme_araci.cli import main

        with self.assertRaises(SystemExit) as ctx:
            main(["--version"])
        self.assertEqual(ctx.exception.code, 0)

    def test_version_command(self) -> None:
        from sifreleme_araci.cli import main

        self.assertEqual(main(["version"]), 0)

    def test_self_check(self) -> None:
        from sifreleme_araci.cli import main

        self.assertEqual(main(["self-check"]), 0)

    def test_encrypt_decrypt_via_cli(self) -> None:
        from sifreleme_araci.cli import main

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "t.bsa"
            code = main(
                [
                    "encrypt",
                    "-t",
                    "cli-smoke",
                    "-o",
                    str(out),
                    "--password",
                    "cli-pw",
                ]
            )
            self.assertEqual(code, 0)
            self.assertTrue(out.is_file())
            self.assertEqual(
                main(["verify", "-i", str(out), "--password", "cli-pw"]),
                0,
            )
            self.assertEqual(main(["inspect", "-i", str(out), "--json"]), 0)

    def test_inspect_table(self) -> None:
        from sifreleme_araci.cli import main

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "t.bsa"
            main(["encrypt", "-t", "x", "-o", str(out), "--password", "p"])
            self.assertEqual(main(["inspect", "-i", str(out)]), 0)

    def test_benchmark_small(self) -> None:
        from sifreleme_araci.cli import main

        self.assertEqual(
            main(["benchmark", "--sizes", "0,64", "--rounds", "1"]),
            0,
        )

    def test_audit_log_has_no_password(self) -> None:
        from sifreleme_araci.cli import main

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "t.bsa"
            audit = Path(tmp) / "audit.jsonl"
            code = main(
                [
                    "--audit-log",
                    str(audit),
                    "encrypt",
                    "-t",
                    "secret-text",
                    "-o",
                    str(out),
                    "--password",
                    "AuditPass123!",
                ]
            )
            self.assertEqual(code, 0)
            text = audit.read_text(encoding="utf-8")
            self.assertIn("encrypt_ok", text)
            self.assertNotIn("AuditPass123!", text)
            self.assertNotIn("secret-text", text)

    def test_secure_write_creates_file(self) -> None:
        from sifreleme_araci.cli import _write_bytes_secure

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "out.bin"
            _write_bytes_secure(path, b"abc")
            self.assertEqual(path.read_bytes(), b"abc")


if __name__ == "__main__":
    unittest.main()
