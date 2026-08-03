"""Keşif, protect ve keyfile birim testleri."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from sifreleme_araci.crypto_ops import decrypt_bytes
from sifreleme_araci.discovery import mask_secret, scan_path, scan_text
from sifreleme_araci.secrets_io import read_keyfile, resolve_secret


class DiscoveryTests(unittest.TestCase):
    def test_mask_secret(self) -> None:
        self.assertEqual(mask_secret("abcdefgh"), "ab****gh")

    def test_scan_text_finds_email_and_iban(self) -> None:
        text = "mail: a@b.com IBAN TR33 0006 1005 1978 6457 8413 26"
        kinds = {f.kind for f in scan_text(text)}
        self.assertIn("email", kinds)
        self.assertIn("iban_tr", kinds)

    def test_scan_sample_dir(self) -> None:
        root = Path(__file__).resolve().parents[1] / "ornekler" / "hassas_ornek"
        report = scan_path(root)
        self.assertGreaterEqual(report.files_scanned, 3)
        self.assertGreater(report.finding_count, 0)
        self.assertIn("email", report.by_kind)
        # Ham PII maskeli
        for finding in report.findings:
            self.assertNotIn("@", finding.masked)  # email maskelenmiş
            self.assertIn("*", finding.masked)


class KeyfileTests(unittest.TestCase):
    def test_read_keyfile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "k.key"
            path.write_text("# yorum\nvault-secret-ok\n", encoding="utf-8")
            self.assertEqual(read_keyfile(path), "vault-secret-ok")

    def test_resolve_rejects_both(self) -> None:
        with self.assertRaises(Exception):
            resolve_secret(
                password="x",
                keyfile="y",
                confirm=False,
                get_password=lambda confirm: "z",
            )

    def test_encrypt_decrypt_with_keyfile_cli(self) -> None:
        from sifreleme_araci.cli import main

        with tempfile.TemporaryDirectory() as tmp:
            key = Path(tmp) / "vault.key"
            key.write_text("vault-demo-secret-OK", encoding="utf-8")
            out = Path(tmp) / "t.bsa"
            code = main(
                [
                    "encrypt",
                    "-t",
                    "keyfile-smoke",
                    "-o",
                    str(out),
                    "--keyfile",
                    str(key),
                ]
            )
            self.assertEqual(code, 0)
            self.assertEqual(
                main(["verify", "-i", str(out), "--keyfile", str(key)]),
                0,
            )


class ScanProtectCliTests(unittest.TestCase):
    def test_scan_cli(self) -> None:
        from sifreleme_araci.cli import main

        root = Path(__file__).resolve().parents[1] / "ornekler" / "hassas_ornek"
        self.assertEqual(main(["scan", "-i", str(root), "--summary"]), 0)
        self.assertEqual(main(["scan", "-i", str(root), "--json"]), 0)

    def test_protect_dry_run_and_real(self) -> None:
        from sifreleme_araci.cli import main

        root = Path(__file__).resolve().parents[1] / "ornekler" / "hassas_ornek"
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "protected"
            self.assertEqual(
                main(
                    [
                        "protect",
                        "-i",
                        str(root),
                        "-o",
                        str(out),
                        "--dry-run",
                    ]
                ),
                0,
            )
            code = main(
                [
                    "protect",
                    "-i",
                    str(root),
                    "-o",
                    str(out),
                    "--password",
                    "ProtectPass-2026!",
                ]
            )
            self.assertEqual(code, 0)
            bsa_files = list(out.rglob("*.bsa"))
            self.assertGreaterEqual(len(bsa_files), 1)
            # En az bir paket çözülür
            blob = bsa_files[0].read_bytes()
            plain = decrypt_bytes(blob, "ProtectPass-2026!")
            self.assertTrue(len(plain) > 0)

    def test_audit_scan_has_no_raw_email(self) -> None:
        from sifreleme_araci.cli import main

        root = Path(__file__).resolve().parents[1] / "ornekler" / "hassas_ornek"
        with tempfile.TemporaryDirectory() as tmp:
            audit = Path(tmp) / "a.jsonl"
            code = main(
                [
                    "--audit-log",
                    str(audit),
                    "scan",
                    "-i",
                    str(root),
                    "--summary",
                ]
            )
            self.assertEqual(code, 0)
            text = audit.read_text(encoding="utf-8")
            self.assertIn("scan_ok", text)
            self.assertNotIn("ayse.yilmaz@ornek.com", text)


if __name__ == "__main__":
    unittest.main()
