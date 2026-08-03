# Security Policy

Bu depo kişisel / eğitim amaçlı bir şifreleme CLI’sidir. Yine de güvenlik bulgularını ciddiye alırız.

## Desteklenen sürümler

| Sürüm | Destek |
|---|---|
| 1.3.x | Aktif |
| 1.2.x | Güvenlik düzeltmeleri |
| < 1.2 | Desteklenmiyor |

## Güvenlik açığı bildirimi

**Lütfen açık issue’da exploit PoC veya hassas detay yayınlamayın.**

1. Bulguyu private olarak bildirin: GitHub **Security → Advisories → Report a vulnerability**, veya maintainer’a özel mesaj.
2. Etki özeti, etkilenen sürüm, yeniden üretim adımları (mümkünse minimal) ekleyin.
3. Makul yanıt süresi hedefi: **7 gün içinde ilk geri bildirim**.

Koordineli açıklama (CVD) tercih edilir. Kritik auth bypass / AEAD doğrulama atlama hemen ele alınır.

## Kapsam (in-scope)

- AEAD doğrulamasının atlanması
- Yanlış parola / manipülasyon ayrımı sızdıran hata kanalları
- Parola, anahtar veya plaintext’in log/audit’e yazılması
- Format parser üzerinden beklenmeyen davranış
- Bağımlılık (`cryptography`) bilinen CVE’lerinin yansıtılmaması

## Kapsam dışı (out-of-scope)

- Zayıf kullanıcı parolası (Scrypt maliyeti bilinçli trade-off)
- OS bellek dökümü / cold-boot
- `--password` CLI anti-pattern’inin bilerek kullanımı
- Fiziksel erişim, keylogger, sosyal mühendislik
- “Kendi algoritmam daha güvenli” önerileri

## Güvenli kullanım özeti

- Parolayı interaktif `getpass` ile girin; `--password` kullanmayın.
- Çözülmüş dosyaları güvenli silin / kısıtlı izinle saklayın.
- `verify` ile bütünlüğü plaintext yazmadan kontrol edin.
- Bağımlılıkları güncel tutun (`pip-audit` CI’da çalışır).

Teknik tehdit modeli: [`report.md`](./report.md) · Kontrol eşlemesi: [`SECURITY.md` § Controls](#controls-mapping-junior-bar)

## Controls mapping (junior bar)

| Beklenti (JR SecEng) | Bu projedeki karşılık |
|---|---|
| Doğru crypto kullanımı | AES-256-GCM + Scrypt; kendi algo yok |
| Threat model | `report.md` STRIDE özeti |
| Secure defaults | Atomik yazma, POSIX `0o600`, getpass |
| Fail closed | Tag fail → plaintext yok |
| Oracle azaltma | Tek auth hata mesajı |
| Input / resource limit | `BSA_MAX_BYTES` / `LimitError` |
| Secrets in logs yok | Audit JSONL yasaklı alanlar |
| SAST | CI: Bandit |
| Dependency hygiene | CI: pip-audit |
| Disclosure process | Bu dosya |
| Test edilmiş negatif yollar | Yanlış parola, tamper, format |
