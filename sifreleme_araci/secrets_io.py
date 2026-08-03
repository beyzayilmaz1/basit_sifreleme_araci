"""
Kimlik bilgisi / anahtar materyali okuma yardımcıları.

Delinea PAM metaforu (öğrenme ölçeği):
  - Parola: kullanıcının bildiği düşük entropili girdi
  - Keyfile: vault'tan çekilmiş yüksek entropili secret dosyası

Her ikisi de Scrypt'e girer; keyfile "daha güvenli şifreleme" değil,
"anahtar kaynağını ayırma" disiplinidir.
"""

from __future__ import annotations

from pathlib import Path

from sifreleme_araci.crypto_ops import CryptoError


def read_keyfile(path: Path) -> str:
    """
    Keyfile içeriğini parola yerine kullanılabilecek secret olarak okur.

    - Boş satırlar ve sonda newline strip edilir
    - # ile başlayan satırlar yorum sayılır (ilk satır secret ise korunur:
      yalnızca satır tamamen yorum ise atlanır; içerik tek satır beklenir)
    - Secret process listesine yazılmaz; çağıran getpass yerine bunu kullanır
    """
    if not path.is_file():
        raise CryptoError(f"Keyfile bulunamadı: {path}")
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise CryptoError(f"Keyfile okunamadı: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise CryptoError("Keyfile UTF-8 metin olmalı.") from exc

    lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
    # Yalnızca yorum satırı olanları çıkar; en az bir secret satırı kalsın.
    secret_lines = [ln for ln in lines if not ln.startswith("#")]
    if not secret_lines:
        raise CryptoError("Keyfile boş veya yalnızca yorum satırı içeriyor.")
    secret = secret_lines[0]
    if len(secret) < 8:
        raise CryptoError(
            "Keyfile secret'ı çok kısa (en az 8 karakter). "
            "Vault benzeri keyfile yüksek entropi taşımalıdır."
        )
    return secret


def resolve_secret(
    *,
    password: str | None,
    keyfile: str | None,
    confirm: bool,
    get_password,
) -> tuple[str, str]:
    """
    Parola veya keyfile'dan secret üretir.

    Dönüş: (secret, source) — source 'password' | 'keyfile' | 'password_flag'
    get_password: confirm alan CLI callback'i (args, confirm) -> str
    """
    if password is not None and keyfile is not None:
        raise CryptoError("--password ve --keyfile birlikte kullanılamaz.")
    if keyfile is not None:
        return read_keyfile(Path(keyfile)), "keyfile"
    if password is not None:
        # Bayraklı parola: CLI tarafı uyarı basar.
        return password, "password_flag"
    return get_password(confirm=confirm), "password"
