#!/usr/bin/env python3
"""
Canlı demo senaryosu — sunum için tek komutluk akış.

Kullanım (proje kökünden):
  set PYTHONPATH=.
  python ornekler/demo.py
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("PYTHONPATH", str(ROOT))

from sifreleme_araci.cli import main  # noqa: E402


def step(title: str) -> None:
    print()
    print("=" * 60)
    print(title)
    print("=" * 60)


def run(argv: list[str]) -> None:
    print("$ python -m sifreleme_araci", " ".join(argv))
    code = main(argv)
    if code != 0:
        raise SystemExit(code)


def main_demo() -> int:
    sample = ROOT / "ornekler" / "ornek.txt"
    hassas = ROOT / "ornekler" / "hassas_ornek"
    keyfile = ROOT / "ornekler" / "vault.key.example"
    password = "Demo-Parola-2026!"

    with tempfile.TemporaryDirectory(prefix="bsa-demo-") as tmp:
        tmp_path = Path(tmp)
        enc = tmp_path / "ornek.txt.bsa"
        dec = tmp_path / "ornek_cozulu.txt"
        protected = tmp_path / "protected"
        audit = tmp_path / "audit.jsonl"
        enc_key = tmp_path / "keyfile.bsa"

        step("1) Sürüm")
        run(["version"])

        step("2) Self-check")
        run(["self-check"])

        step("3) Şifrele")
        run(
            [
                "encrypt",
                "-i",
                str(sample),
                "-o",
                str(enc),
                "--password",
                password,
            ]
        )

        step("4) Inspect (tablo)")
        run(["inspect", "-i", str(enc)])

        step("5) Verify (plaintext yazmadan)")
        run(["verify", "-i", str(enc), "--password", password])

        step("6) Decrypt")
        run(
            [
                "decrypt",
                "-i",
                str(enc),
                "-o",
                str(dec),
                "--password",
                password,
            ]
        )

        step("7) Yanlış parola (beklenen hata)")
        code = main(["verify", "-i", str(enc), "--password", "yanlis"])
        assert code == 1, "yanlış parola reddedilmeli"

        step("8) scan — hassas veri keşfi (Voltage)")
        run(["--audit-log", str(audit), "scan", "-i", str(hassas), "--summary"])

        step("9) protect --dry-run")
        run(
            [
                "protect",
                "-i",
                str(hassas),
                "-o",
                str(protected),
                "--dry-run",
            ]
        )

        step("10) keyfile ile şifrele (Delinea / vault metaforu)")
        run(
            [
                "encrypt",
                "-t",
                "vault-secret-demo",
                "-o",
                str(enc_key),
                "--keyfile",
                str(keyfile),
            ]
        )
        run(["verify", "-i", str(enc_key), "--keyfile", str(keyfile)])

        step("11) Mini benchmark")
        run(["benchmark", "--sizes", "0,1024,65536", "--rounds", "1"])

        print()
        print("Demo tamamlandı. Çözülen dosya boyutu:", dec.stat().st_size, "bayt")
        print("Audit satır sayısı:", len(audit.read_text(encoding="utf-8").splitlines()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main_demo())
