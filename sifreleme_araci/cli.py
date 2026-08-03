"""
Komut satırı arayüzü.

Örnekler:
  python -m sifreleme_araci encrypt -t "gizli not" -o not.bsa
  python -m sifreleme_araci encrypt -i rapor.pdf -o rapor.pdf.bsa
  python -m sifreleme_araci decrypt -i not.bsa
  python -m sifreleme_araci decrypt -i rapor.pdf.bsa -o rapor.pdf
  python -m sifreleme_araci inspect -i not.bsa
  python -m sifreleme_araci verify -i not.bsa
  python -m sifreleme_araci benchmark
  python -m sifreleme_araci self-check
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import time
from pathlib import Path

from sifreleme_araci import __version__
from sifreleme_araci.crypto_ops import (
    MAGIC,
    VERSION,
    CryptoError,
    assess_password_strength,
    decrypt_bytes,
    describe_blob,
    encrypt_bytes,
    verify_blob,
)
from sifreleme_araci.discovery import (
    files_needing_protection,
    scan_path,
)
from sifreleme_araci.secrets_io import resolve_secret

# Büyük dosyalarda aşama bilgisi eşiği (bayt).
_PROGRESS_THRESHOLD = 256 * 1024


# ---------------------------------------------------------------------------
# Terminal yardımcıları (ek bağımlılık yok)
# ---------------------------------------------------------------------------


def _color_enabled() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return sys.stdout.isatty()


def _enable_windows_ansi() -> None:
    if sys.platform != "win32":
        return
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        pass


def _c(text: str, code: str) -> str:
    if not _color_enabled():
        return text
    return f"\033[{code}m{text}\033[0m"


def _ok(msg: str) -> None:
    print(_c("OK", "32") + f"  {msg}")


def _info(msg: str) -> None:
    print(_c("::", "36") + f" {msg}")


def _warn(msg: str) -> None:
    print(_c("Uyarı:", "33") + f" {msg}", file=sys.stderr)


def _err(msg: str) -> None:
    print(_c("Hata:", "31") + f" {msg}", file=sys.stderr)


def _stage(msg: str) -> None:
    if sys.stderr.isatty():
        print(_c("…", "90") + f" {msg}", file=sys.stderr)


def _print_table(rows: list[tuple[str, str]]) -> None:
    key_w = max((len(k) for k, _ in rows), default=0)
    for key, value in rows:
        label = _c(f"{key:<{key_w}}", "1") if _color_enabled() else f"{key:<{key_w}}"
        print(f"  {label}  {value}")


def _write_bytes_secure(path: Path, data: bytes) -> None:
    """
    Atomik yazma + Unix'te 0o600 izin (umask'tan bağımsız hedef).

    Kısmi .bsa / plaintext dosyası bırakmamak ve world-readable çıktıyı
    azaltmak JR SecEng secure-default beklentisidir.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    # 0o600: sahip okuma/yazma; grup/diğer yok (POSIX). Windows'ta yaklaşık.
    fd = os.open(str(tmp), flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(str(tmp), str(path))
        if os.name == "posix":
            os.chmod(path, 0o600)
    except Exception:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise


# SIEM / Splunk tarzı sabit olay adları (docs/siem-mapping.md ile hizalı).
KNOWN_AUDIT_EVENTS = frozenset(
    {
        "encrypt_ok",
        "encrypt_fail",
        "decrypt_ok",
        "decrypt_fail",
        "verify_ok",
        "verify_fail",
        "scan_ok",
        "protect_ok",
        "protect_fail",
        "auth_source",
    }
)


def _audit(event: str, **fields: object) -> None:
    """
    Güvenlik olayı kaydı. Parola / plaintext / key / PII ASLA yazılmaz.

    BSA_AUDIT_LOG=/path/to.jsonl veya --audit-log ile etkinleşir.
    Alanlar Splunk/ELK'ye JSONL olarak alınabilir (docs/siem-mapping.md).
    """
    dest = os.environ.get("BSA_AUDIT_LOG")
    if not dest:
        return
    if event not in KNOWN_AUDIT_EVENTS:
        # Bilinmeyen olay yine yazılır; geliştirme sırasında fark edilsin.
        fields = {**fields, "event_unlisted": True}
    banned = {
        "password",
        "passwd",
        "plaintext",
        "key",
        "secret",
        "keyfile_content",
        "pii",
        "finding",
        "masked",
    }
    safe = {k: v for k, v in fields.items() if k.lower() not in banned}
    record = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event": event,
        "event_source": "sifreleme_araci",
        "tool": "sifreleme_araci",
        "version": __version__,
        "vendor_product": "basit_sifreleme_araci",
        **safe,
    }
    line = json.dumps(record, ensure_ascii=False) + "\n"
    try:
        with open(dest, "a", encoding="utf-8") as handle:
            handle.write(line)
    except OSError as exc:
        _warn(f"audit log yazılamadı: {exc}")


# ---------------------------------------------------------------------------
# Girdi yardımcıları
# ---------------------------------------------------------------------------


def _interactive_password(*, confirm: bool) -> str:
    pw = getpass.getpass("Parola: ")
    if confirm:
        pw2 = getpass.getpass("Parola (tekrar): ")
        if pw != pw2:
            raise CryptoError("Parolalar eşleşmiyor.")
    return pw


def _read_password(args: argparse.Namespace, *, confirm: bool) -> str:
    """
    Secret alır: interaktif parola, --password (demo) veya --keyfile (vault metaforu).
    """
    password = getattr(args, "password", None)
    keyfile = getattr(args, "keyfile", None)

    if password is not None:
        _warn(
            "--password komut satırında görünür (ps/history). "
            "Gerçek kullanımda interaktif veya --keyfile tercih edin."
        )

    def _get(*, confirm: bool) -> str:
        return _interactive_password(confirm=confirm)

    pw, source = resolve_secret(
        password=password,
        keyfile=keyfile,
        confirm=confirm,
        get_password=_get,
    )
    _audit("auth_source", auth_source=source)

    if source != "keyfile":
        warning = assess_password_strength(pw)
        if warning and confirm:
            _warn(warning)
    elif confirm:
        _info("Secret kaynağı: keyfile (PAM/vault metaforu)")
    return pw


def _read_plaintext(args: argparse.Namespace) -> bytes:
    if args.text is not None and args.input is not None:
        raise CryptoError("-t/--text ve -i/--input birlikte kullanılamaz.")
    if args.text is not None:
        return args.text.encode("utf-8")
    if args.input is not None:
        path = Path(args.input)
        if not path.is_file():
            raise CryptoError(f"Girdi dosyası bulunamadı: {path}")
        data = path.read_bytes()
        # Boş dosya kasıtlı olarak desteklenir (sağlamlık kontrol noktası).
        return data
    # stdin
    if sys.stdin.isatty():
        raise CryptoError(
            "Girdi yok. -t/--text, -i/--input kullanın veya stdin'e pipe edin."
        )
    return sys.stdin.buffer.read()


def _read_blob(args: argparse.Namespace) -> bytes:
    if args.input is None:
        if sys.stdin.isatty():
            raise CryptoError("Çözülecek dosya için -i/--input gerekli (veya stdin).")
        return sys.stdin.buffer.read()
    path = Path(args.input)
    if not path.is_file():
        raise CryptoError(f"Girdi dosyası bulunamadı: {path}")
    return path.read_bytes()


# ---------------------------------------------------------------------------
# Komutlar
# ---------------------------------------------------------------------------


def cmd_encrypt(args: argparse.Namespace) -> int:
    plaintext = _read_plaintext(args)
    password = _read_password(args, confirm=True)
    if len(plaintext) >= _PROGRESS_THRESHOLD:
        _stage(f"şifreleniyor ({len(plaintext)} bayt)…")
    try:
        blob = encrypt_bytes(plaintext, password)
    except CryptoError:
        _audit("encrypt_fail", reason="crypto_error", size=len(plaintext))
        raise

    if args.output:
        out = Path(args.output)
        _write_bytes_secure(out, blob)
        _ok(f"Şifrelendi → {out} ({len(blob)} bayt)")
        _audit("encrypt_ok", output=str(out), ciphertext_len=len(blob))
    else:
        # Binary stdout; Windows'ta text mode bozar, buffer kullan.
        sys.stdout.buffer.write(blob)
        _audit("encrypt_ok", output="stdout", ciphertext_len=len(blob))
    return 0


def cmd_decrypt(args: argparse.Namespace) -> int:
    blob = _read_blob(args)
    password = _read_password(args, confirm=False)
    if len(blob) >= _PROGRESS_THRESHOLD:
        _stage(f"çözülüyor ({len(blob)} bayt)…")
    try:
        plaintext = decrypt_bytes(blob, password)
    except CryptoError as exc:
        _audit(
            "decrypt_fail",
            input=str(getattr(args, "input", None) or "stdin"),
            error_type=type(exc).__name__,
        )
        raise

    if args.output:
        out = Path(args.output)
        _write_bytes_secure(out, plaintext)
        _ok(f"Çözüldü → {out} ({len(plaintext)} bayt)")
        _audit("decrypt_ok", output=str(out), plaintext_len=len(plaintext))
    else:
        # Metin gibi görünüyorsa decode etmeye çalış; değilse binary yaz.
        try:
            text = plaintext.decode("utf-8")
        except UnicodeDecodeError:
            sys.stdout.buffer.write(plaintext)
        else:
            # Windows konsol encoding sorunlarına karşı errors='replace'
            sys.stdout.write(text)
            if not text.endswith("\n"):
                sys.stdout.write("\n")
        _audit("decrypt_ok", output="stdout", plaintext_len=len(plaintext))
    return 0


def cmd_inspect(args: argparse.Namespace) -> int:
    path = Path(args.input)
    if not path.is_file():
        raise CryptoError(f"Dosya bulunamadı: {path}")
    meta = describe_blob(path.read_bytes())

    if args.json:
        print(json.dumps(meta, indent=2, ensure_ascii=False))
        return 0

    rows = [
        ("Dosya", str(path)),
        ("Magic", meta["magic"]),
        ("Sürüm", str(meta["version"])),
        ("KDF", meta["kdf"]),
        ("Cipher", meta["cipher"]),
        ("Salt", meta["salt_hex"]),
        ("Nonce", meta["nonce_hex"]),
        ("Header", f"{meta['header_len']} bayt"),
        ("Tag", f"{meta['tag_len']} bayt"),
        ("Ciphertext", f"{meta['ciphertext_len']} bayt"),
        ("≈ Plaintext", f"{meta['approx_plaintext_len']} bayt"),
        ("Toplam", f"{meta['total_len']} bayt"),
    ]
    print(_c("BSA paket özeti", "1"))
    _print_table(rows)
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    """Parola + AEAD doğrulaması; plaintext diske yazılmaz."""
    blob = _read_blob(args)
    password = _read_password(args, confirm=False)
    try:
        verify_blob(blob, password)
    except CryptoError as exc:
        _audit(
            "verify_fail",
            input=str(getattr(args, "input", None) or "stdin"),
            error_type=type(exc).__name__,
        )
        raise
    _ok("Doğrulama başarılı (parola doğru, bütünlük sağlam).")
    _audit("verify_ok", input=str(getattr(args, "input", None) or "stdin"))
    return 0


def cmd_benchmark(args: argparse.Namespace) -> int:
    """Scrypt + AES-GCM sürelerini ölçer (sunum / kapasite planı)."""
    sizes = [int(x) for x in args.sizes.split(",") if x.strip()]
    if not sizes or any(s < 0 for s in sizes):
        raise CryptoError("--sizes pozitif bayt listesi olmalı (örn. 1024,65536,1048576).")
    rounds = max(1, args.rounds)
    password = "benchmark-only-password"

    print(_c(f"Benchmark  v{__version__}  rounds={rounds}", "1"))
    print()
    header = f"{'Boyut':>12}  {'Encrypt(ms)':>12}  {'Decrypt(ms)':>12}  {'Toplam(ms)':>12}"
    print(header)
    print("-" * len(header))

    report_rows: list[dict] = []
    for size in sizes:
        pt = os.urandom(size) if size else b""
        enc_ms: list[float] = []
        dec_ms: list[float] = []
        for _ in range(rounds):
            t0 = time.perf_counter()
            blob = encrypt_bytes(pt, password)
            t1 = time.perf_counter()
            out = decrypt_bytes(blob, password)
            t2 = time.perf_counter()
            if out != pt:
                raise CryptoError("Benchmark bütünlük hatası.")
            enc_ms.append((t1 - t0) * 1000)
            dec_ms.append((t2 - t1) * 1000)

        e = sum(enc_ms) / rounds
        d = sum(dec_ms) / rounds
        print(f"{size:>12}  {e:>12.1f}  {d:>12.1f}  {e + d:>12.1f}")
        report_rows.append(
            {
                "size_bytes": size,
                "encrypt_ms_avg": round(e, 2),
                "decrypt_ms_avg": round(d, 2),
                "total_ms_avg": round(e + d, 2),
            }
        )

    if args.json:
        print()
        print(
            json.dumps(
                {
                    "version": __version__,
                    "rounds": rounds,
                    "kdf": "Scrypt(N=16384,r=8,p=1)",
                    "cipher": "AES-256-GCM",
                    "results": report_rows,
                },
                indent=2,
            )
        )
    else:
        print()
        _info("Süreler Scrypt türetmesini içerir; küçük dosyalarda KDF baskındır.")
    return 0


def cmd_self_check(args: argparse.Namespace) -> int:
    """Kurulum / kütüphane / format için dahili sağlık kontrolü."""
    del args  # unused; argparse uyumu
    checks: list[tuple[str, bool, str]] = []

    # 1) Round-trip
    try:
        pw = "self-check-pw"
        pt = "şğüöç ✓".encode("utf-8")
        blob = encrypt_bytes(pt, pw)
        ok = decrypt_bytes(blob, pw) == pt and blob.startswith(MAGIC)
        checks.append(("round-trip + magic", ok, "şifrele/çöz"))
    except Exception as exc:  # noqa: BLE001 — self-check toplar
        checks.append(("round-trip + magic", False, str(exc)))

    # 2) Yanlış parola reddi
    try:
        blob = encrypt_bytes(b"x", "a")
        try:
            decrypt_bytes(blob, "b")
            checks.append(("wrong-password reject", False, "reddedilmedi"))
        except CryptoError:
            checks.append(("wrong-password reject", True, "AuthenticationError yolu"))
    except Exception as exc:  # noqa: BLE001
        checks.append(("wrong-password reject", False, str(exc)))

    # 3) Format sürümü sabiti
    checks.append(("format version", VERSION == 1, f"VERSION={VERSION}"))

    # 4) cryptography import
    try:
        import cryptography

        checks.append(
            ("cryptography import", True, f"v{cryptography.__version__}")
        )
    except Exception as exc:  # noqa: BLE001
        checks.append(("cryptography import", False, str(exc)))

    # 5) boyut limiti sözleşmesi
    try:
        from sifreleme_araci.crypto_ops import LimitError, max_plaintext_bytes

        old = os.environ.get("BSA_MAX_BYTES")
        os.environ["BSA_MAX_BYTES"] = "8"
        try:
            encrypt_bytes(b"0123456789", "long-enough-pw")
            checks.append(("size limit", False, "LimitError beklenirdi"))
        except LimitError:
            checks.append(("size limit", True, "BSA_MAX_BYTES enforced"))
        finally:
            if old is None:
                os.environ.pop("BSA_MAX_BYTES", None)
            else:
                os.environ["BSA_MAX_BYTES"] = old
            _ = max_plaintext_bytes  # import side-effect yok
    except Exception as exc:  # noqa: BLE001
        checks.append(("size limit", False, str(exc)))

    failed = 0
    print(_c(f"Self-check  sifreleme_araci {__version__}", "1"))
    for name, passed, detail in checks:
        if passed:
            _ok(f"{name} — {detail}")
        else:
            failed += 1
            _err(f"{name} — {detail}")

    if failed:
        _err(f"{failed} kontrol başarısız.")
        return 1
    _ok("Tüm kontroller geçti.")
    return 0


def cmd_version(args: argparse.Namespace) -> int:
    del args
    print(f"sifreleme_araci {__version__}")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    """Hassas veri keşfi (Voltage discovery metaforu). Ham PII yazılmaz."""
    root = Path(args.path)
    if not root.exists():
        raise CryptoError(f"Yol bulunamadı: {root}")

    report = scan_path(root)
    _audit(
        "scan_ok",
        path=str(root),
        files_scanned=report.files_scanned,
        files_with_findings=report.files_with_findings,
        finding_count=report.finding_count,
        by_kind=report.by_kind,
    )

    if args.json:
        print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
        return 0

    print(_c("Hassas veri keşfi", "1"))
    _print_table(
        [
            ("Kök", report.root),
            ("Taranan dosya", str(report.files_scanned)),
            ("Bulgulu dosya", str(report.files_with_findings)),
            ("Toplam bulgu", str(report.finding_count)),
            (
                "Türler",
                ", ".join(f"{k}={v}" for k, v in sorted(report.by_kind.items()))
                or "(yok)",
            ),
        ]
    )
    if report.findings and not args.summary:
        print()
        print(_c("Bulgular (maskeli)", "1"))
        for item in report.findings[: args.limit]:
            print(
                f"  [{item.kind}] {item.path}:{item.line}  "
                f"{item.masked}  — {item.description}"
            )
        if len(report.findings) > args.limit:
            _info(f"… {len(report.findings) - args.limit} bulgu daha ( --limit artırın )")
    if report.finding_count == 0:
        _ok("Hassas pattern bulunamadı.")
    else:
        _warn(
            f"{report.finding_count} bulgu. Koruma için: "
            "protect -i <yol> -o <çıktı_klasörü>"
        )
    return 0


def cmd_protect(args: argparse.Namespace) -> int:
    """
    Keşif + şifreleme: bulgulu dosyaları .bsa paketlerine çevirir.

    Voltage "discovery + encryption" akışının demo ölçeği.
    """
    root = Path(args.input)
    if not root.exists():
        raise CryptoError(f"Yol bulunamadı: {root}")
    out_dir = Path(args.output)
    report = scan_path(root)
    targets = files_needing_protection(report)

    if args.json and args.dry_run:
        print(
            json.dumps(
                {
                    "dry_run": True,
                    "scan": report.to_dict(),
                    "would_protect": [str(p) for p in targets],
                },
                indent=2,
                ensure_ascii=False,
            )
        )
        return 0

    if not targets:
        _ok("Şifrelenecek bulgulu dosya yok.")
        _audit(
            "protect_ok",
            path=str(root),
            protected_count=0,
            finding_count=report.finding_count,
            dry_run=bool(args.dry_run),
        )
        return 0

    print(_c("Protect özeti", "1"))
    _print_table(
        [
            ("Kök", str(root.resolve())),
            ("Bulgulu dosya", str(len(targets))),
            ("Bulgu sayısı", str(report.finding_count)),
            ("Türler", ", ".join(f"{k}={v}" for k, v in sorted(report.by_kind.items()))),
            ("Mod", "dry-run" if args.dry_run else "şifrele"),
        ]
    )

    if args.dry_run:
        for path in targets:
            print(f"  would-protect  {path}")
        _info("Dry-run: dosya yazılmadı. Gerçek koruma için --dry-run kaldırın.")
        _audit(
            "protect_ok",
            path=str(root),
            protected_count=0,
            would_protect=len(targets),
            finding_count=report.finding_count,
            dry_run=True,
        )
        return 0

    password = _read_password(args, confirm=True)
    out_dir.mkdir(parents=True, exist_ok=True)
    protected = 0
    for path in targets:
        try:
            plaintext = path.read_bytes()
            blob = encrypt_bytes(plaintext, password)
            # Çıktı adını kök göreli tut; çakışmayı .bsa ile ayır.
            try:
                rel = path.resolve().relative_to(root.resolve())
            except ValueError:
                rel = Path(path.name)
            dest = out_dir / f"{rel}.bsa"
            dest.parent.mkdir(parents=True, exist_ok=True)
            _write_bytes_secure(dest, blob)
            _ok(f"{path.name} → {dest}")
            protected += 1
        except CryptoError:
            _audit(
                "protect_fail",
                path=str(path),
                error_type="CryptoError",
            )
            raise
        except OSError as exc:
            _audit("protect_fail", path=str(path), error_type="OSError")
            raise CryptoError(f"Dosya işlenemedi ({path}): {exc}") from exc

    _audit(
        "protect_ok",
        path=str(root),
        protected_count=protected,
        finding_count=report.finding_count,
        output=str(out_dir),
        dry_run=False,
    )
    _ok(f"{protected} dosya korundu → {out_dir}")
    return 0


# ---------------------------------------------------------------------------
# Parser / main
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sifreleme_araci",
        description=(
            "Basit Şifreleme Aracı — dosya/metin şifreleme CLI. "
            "AES-256-GCM + Scrypt (pyca/cryptography). "
            "Keşif (scan/protect) ve keyfile desteği ile Konsalt güvenlik "
            "portföyü (Voltage / Splunk / Delinea) öğrenme köprüleri içerir. "
            "Kendi kriptografik algoritmanızı içermez."
        ),
        epilog=(
            "Örnekler:\n"
            "  %(prog)s encrypt -t \"gizli\" -o not.bsa\n"
            "  %(prog)s decrypt -i not.bsa\n"
            "  %(prog)s scan -i ornekler/hassas_ornek\n"
            "  %(prog)s protect -i ornekler/hassas_ornek -o out --dry-run\n"
            "  %(prog)s encrypt -i secret.txt -o secret.bsa --keyfile vault.key\n"
            "  %(prog)s self-check\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "--audit-log",
        metavar="PATH",
        help=(
            "Güvenlik olaylarını JSONL dosyasına yaz "
            "(parola/plaintext/PII yazılmaz; BSA_AUDIT_LOG ile de verilebilir). "
            "Splunk/ELK eşlemesi: docs/siem-mapping.md"
        ),
    )

    sub = parser.add_subparsers(dest="command", required=True)

    common_pw = argparse.ArgumentParser(add_help=False)
    common_pw.add_argument(
        "--password",
        help="Parola (yalnızca test/demo; production'da kullanmayın)",
    )
    common_pw.add_argument(
        "--keyfile",
        metavar="PATH",
        help=(
            "Vault/PAM metaforu: secret'ı dosyadan oku "
            "(--password ile birlikte kullanılamaz)"
        ),
    )

    p_enc = sub.add_parser(
        "encrypt",
        parents=[common_pw],
        help="Metin veya dosyayı şifrele",
    )
    p_enc.add_argument("-t", "--text", help="Şifrelenecek düz metin")
    p_enc.add_argument("-i", "--input", help="Şifrelenecek dosya yolu")
    p_enc.add_argument("-o", "--output", help="Çıktı dosyası (.bsa önerilir)")
    p_enc.set_defaults(func=cmd_encrypt)

    p_dec = sub.add_parser(
        "decrypt",
        parents=[common_pw],
        help="Şifreli paketi çöz",
    )
    p_dec.add_argument("-i", "--input", help="Şifreli dosya yolu")
    p_dec.add_argument("-o", "--output", help="Çözülmüş çıktı dosyası")
    p_dec.set_defaults(func=cmd_decrypt)

    p_ins = sub.add_parser(
        "inspect",
        help="Şifreli paketin metadata'sını göster (içeriği açmaz)",
    )
    p_ins.add_argument("-i", "--input", required=True, help="Şifreli dosya")
    p_ins.add_argument(
        "--json",
        action="store_true",
        help="Çıktıyı JSON olarak yaz (varsayılan: tablo)",
    )
    p_ins.set_defaults(func=cmd_inspect)

    p_ver = sub.add_parser(
        "verify",
        parents=[common_pw],
        help="Parola ve bütünlüğü doğrula (plaintext yazmaz)",
    )
    p_ver.add_argument("-i", "--input", help="Şifreli dosya yolu")
    p_ver.set_defaults(func=cmd_verify)

    p_scan = sub.add_parser(
        "scan",
        help="Hassas veri keşfi (Voltage discovery metaforu)",
    )
    p_scan.add_argument(
        "-i",
        "--path",
        required=True,
        help="Taranacak dosya veya klasör",
    )
    p_scan.add_argument(
        "--json",
        action="store_true",
        help="JSON rapor (maskeli bulgular)",
    )
    p_scan.add_argument(
        "--summary",
        action="store_true",
        help="Yalnızca özet; bulgu listesini yazma",
    )
    p_scan.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Listelenecek maksimum bulgu (varsayılan: 50)",
    )
    p_scan.set_defaults(func=cmd_scan)

    p_prot = sub.add_parser(
        "protect",
        parents=[common_pw],
        help="Keşif + şifreleme (bulgulu dosyaları .bsa yap)",
    )
    p_prot.add_argument(
        "-i",
        "--input",
        required=True,
        help="Taranacak dosya veya klasör",
    )
    p_prot.add_argument(
        "-o",
        "--output",
        required=True,
        help="Şifreli çıktı klasörü",
    )
    p_prot.add_argument(
        "--dry-run",
        action="store_true",
        help="Şifrelemeden yalnızca ne korunacağını göster",
    )
    p_prot.add_argument(
        "--json",
        action="store_true",
        help="Dry-run ile birlikte JSON planı yaz",
    )
    p_prot.set_defaults(func=cmd_protect)

    p_bench = sub.add_parser(
        "benchmark",
        help="Scrypt + AES-GCM sürelerini ölç",
    )
    p_bench.add_argument(
        "--sizes",
        default="0,1024,65536,1048576",
        help="Virgülle ayrılmış bayt boyutları (varsayılan: 0,1KiB,64KiB,1MiB)",
    )
    p_bench.add_argument(
        "--rounds",
        type=int,
        default=3,
        help="Her boyut için tekrar sayısı (varsayılan: 3)",
    )
    p_bench.add_argument(
        "--json",
        action="store_true",
        help="Sonuçları JSON rapor olarak da yaz",
    )
    p_bench.set_defaults(func=cmd_benchmark)

    p_sc = sub.add_parser(
        "self-check",
        help="Kurulum ve temel güvenlik sözleşmelerini doğrula",
    )
    p_sc.set_defaults(func=cmd_self_check)

    p_v = sub.add_parser("version", help="Sürüm bilgisini yaz")
    p_v.set_defaults(func=cmd_version)

    return parser


def _configure_stdio() -> None:
    """Windows cp1254 konsolunda Unicode print hatalarını azaltır."""
    _enable_windows_ansi()
    for stream in (sys.stdout, sys.stderr):
        reconf = getattr(stream, "reconfigure", None)
        if callable(reconf):
            try:
                reconf(encoding="utf-8", errors="replace")
            except Exception:
                pass


def main(argv: list[str] | None = None) -> int:
    _configure_stdio()
    parser = build_parser()
    args = parser.parse_args(argv)
    override = getattr(args, "audit_log", None)
    previous_audit = os.environ.get("BSA_AUDIT_LOG")
    if override:
        os.environ["BSA_AUDIT_LOG"] = override
    try:
        return args.func(args)
    except CryptoError as exc:
        _err(str(exc))
        return 1
    except KeyboardInterrupt:
        print("\nIptal edildi.", file=sys.stderr)
        return 130
    finally:
        # --audit-log yalnızca bu çağrı için geçerli olsun (unittest aynı süreç).
        if override is not None:
            if previous_audit is None:
                os.environ.pop("BSA_AUDIT_LOG", None)
            else:
                os.environ["BSA_AUDIT_LOG"] = previous_audit


if __name__ == "__main__":
    raise SystemExit(main())
