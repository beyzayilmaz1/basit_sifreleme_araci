"""
Şifreleme çekirdeği.

Kasıtlı olarak yalnızca pyca/cryptography'nin olgun primitives'lerini kullanır:
  - Anahtar türetme : Scrypt (RFC 7914)
  - Şifreleme       : AES-256-GCM (AEAD)

Kendi blok şifresi, kendi MAC'i veya kendi KDF'imiz YOK.
Neden? → bkz. report.md
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# --- Dosya formatı sabiti ---------------------------------------------------
# | magic(4) | version(1) | salt(16) | nonce(12) | ciphertext || tag(16) |
MAGIC = b"BSA1"  # Basit Sifreleme Araci, format v1
VERSION = 1
SALT_LEN = 16
NONCE_LEN = 12  # AES-GCM için önerilen uzunluk (NIST SP 800-38D)
KEY_LEN = 32  # AES-256
TAG_LEN = 16  # AES-GCM authentication tag
HEADER_LEN = 4 + 1 + SALT_LEN + NONCE_LEN  # 33
MIN_BLOB_LEN = HEADER_LEN + TAG_LEN

# Scrypt parametreleri — interaktif CLI için dengeli (güvenlik / süre).
# N=2^14, r=8, p=1 ≈ modern laptop'ta ~50–150 ms.
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1

# Auth başarısızlıklarında tek mesaj (oracle daraltma).
_AUTH_FAIL_MSG = "Çözme başarısız. Parola yanlış veya veri bozulmuş olabilir."

# Bellek DoS / yanlışlıkla devasa girdi koruması (override: BSA_MAX_BYTES).
DEFAULT_MAX_PLAINTEXT = 256 * 1024 * 1024  # 256 MiB
MIN_PASSWORD_WARN_LEN = 8  # soft policy; işlem reddedilmez


class CryptoError(Exception):
    """Kullanıcıya gösterilebilir, güvenli hata mesajı taşır."""


class FormatError(CryptoError):
    """Paket formatı geçersiz (magic, sürüm, uzunluk). Auth öncesi reddedilir."""


class AuthenticationError(CryptoError):
    """AEAD doğrulaması başarısız (yanlış parola veya manipülasyon)."""


class LimitError(CryptoError):
    """Kaynak / boyut limiti aşıldı (DoS azaltma)."""


@dataclass(frozen=True)
class Envelope:
    """Şifreli paketin ayrıştırılmış hali (ciphertext tag dahil)."""

    version: int
    salt: bytes
    nonce: bytes
    ciphertext: bytes


def _aad_for(version: int) -> bytes:
    """Format kimliğini AEAD associated data olarak bağlar."""
    return MAGIC + bytes([version])


def _wipe(buf: bytearray) -> None:
    """Mümkün olduğunca anahtar materyalini bellekten siler."""
    for i in range(len(buf)):
        buf[i] = 0


def _derive_key(password: str, salt: bytes) -> bytearray:
    """Paroladan 256-bit anahtar türetir (Scrypt). Dönüş: silinebilir bytearray."""
    if not password:
        raise CryptoError("Parola boş olamaz.")
    kdf = Scrypt(
        salt=salt,
        length=KEY_LEN,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
    )
    return bytearray(kdf.derive(password.encode("utf-8")))


def max_plaintext_bytes() -> int:
    """Üst boyut limiti (bayt). Ortam: BSA_MAX_BYTES."""
    raw = os.environ.get("BSA_MAX_BYTES")
    if raw is None or not raw.strip():
        return DEFAULT_MAX_PLAINTEXT
    try:
        value = int(raw)
    except ValueError as exc:
        raise LimitError("BSA_MAX_BYTES tam sayı olmalı.") from exc
    if value < 0:
        raise LimitError("BSA_MAX_BYTES negatif olamaz.")
    return value


def assess_password_strength(password: str) -> str | None:
    """
    Soft parola uyarısı döndürür; None = uyarı yok.

    Reddetmez — güvenlik mühendisliği eğitimi / operasyonel bilinç içindir.
    """
    if len(password) < MIN_PASSWORD_WARN_LEN:
        return (
            f"Parola {MIN_PASSWORD_WARN_LEN} karakterden kısa; "
            "çevrimdışı kaba kuvvet riski yükselir."
        )
    return None


def encrypt_bytes(plaintext: bytes, password: str) -> bytes:
    """
    Düz metni şifreler; geri dönüş değeri dosyaya yazılmaya hazır envelope'dur.

    Her çağrıda yeni salt + yeni nonce üretilir → aynı parola + aynı metin
    bile farklı ciphertext verir (semantik güvenlik / IND-CPA beklentisi).
    """
    limit = max_plaintext_bytes()
    if len(plaintext) > limit:
        raise LimitError(
            f"Girdi çok büyük ({len(plaintext)} bayt > limit {limit}). "
            "BSA_MAX_BYTES ile artırılabilir."
        )

    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = _derive_key(password, salt)
    try:
        aesgcm = AESGCM(bytes(key))
        # associated_data olarak MAGIC||VERSION bağlarız: format değişince
        # eski ciphertext yanlışlıkla yeni parser ile açılmaz (bağlama bütünlüğü).
        ciphertext = aesgcm.encrypt(nonce, plaintext, _aad_for(VERSION))
    finally:
        _wipe(key)

    return MAGIC + bytes([VERSION]) + salt + nonce + ciphertext


def _parse_header(blob: bytes) -> Envelope:
    """Envelope başlığını doğrular ve alanlara ayırır (şifre çözmez)."""
    if len(blob) < MIN_BLOB_LEN:
        raise FormatError(
            "Dosya çok kısa veya bozuk: geçerli bir şifreli paket değil."
        )

    magic = blob[:4]
    if magic != MAGIC:
        # Magic herkese açık format kimliği; yine de beklenen sabiti echo etmiyoruz.
        raise FormatError("Geçersiz dosya formatı: magic uyuşmuyor.")

    version = blob[4]
    if version != VERSION:
        raise FormatError(f"Desteklenmeyen format sürümü: {version}")

    return Envelope(
        version=version,
        salt=blob[5 : 5 + SALT_LEN],
        nonce=blob[5 + SALT_LEN : HEADER_LEN],
        ciphertext=blob[HEADER_LEN:],
    )


def decrypt_bytes(blob: bytes, password: str) -> bytes:
    """Envelope'u çözer. Yanlış parola / bozulmuş veri → AuthenticationError."""
    env = _parse_header(blob)
    key = _derive_key(password, env.salt)
    try:
        aesgcm = AESGCM(bytes(key))
        try:
            return aesgcm.decrypt(env.nonce, env.ciphertext, _aad_for(env.version))
        except InvalidTag as exc:
            # Bilinçli olarak tek mesaj: timing/oracle sızıntısını daraltmak +
            # saldırgana "salt yanlış mı / tag mı / parola mı" ayrımı vermemek.
            raise AuthenticationError(_AUTH_FAIL_MSG) from exc
    finally:
        _wipe(key)


def parse_envelope(blob: bytes) -> Envelope:
    """Debug / inceleme için envelope alanlarını ayırır (şifre çözmez)."""
    return _parse_header(blob)


def describe_blob(blob: bytes) -> dict:
    """CLI `inspect` komutu için insan-okur metadata."""
    env = parse_envelope(blob)
    return {
        "magic": MAGIC.decode("ascii"),
        "version": env.version,
        "salt_hex": env.salt.hex(),
        "nonce_hex": env.nonce.hex(),
        "ciphertext_len": len(env.ciphertext),
        "approx_plaintext_len": max(0, len(env.ciphertext) - TAG_LEN),
        "header_len": HEADER_LEN,
        "tag_len": TAG_LEN,
        "total_len": len(blob),
        "kdf": f"Scrypt(N={SCRYPT_N}, r={SCRYPT_R}, p={SCRYPT_P})",
        "cipher": "AES-256-GCM",
    }


def verify_blob(blob: bytes, password: str) -> bool:
    """
    Paketi çözer ama plaintext döndürmez; bütünlük + parola doğrular.

    Başarılıysa True; format/auth hataları CryptoError olarak yükselir.
    """
    plaintext = decrypt_bytes(blob, password)
    # İsteğe bağlı wipe: bytes immutable; referansı bırakmak yeterli sinyal.
    del plaintext
    return True
