# SIEM Mapping — Splunk / ELK öğrenme köprüsü

Bu doküman, `sifreleme_araci` audit JSONL çıktısının
[Konsalt Güvenlik Çözümleri](https://www.konsalt.com.tr/cozumlerimiz/guvenlik-cozumleri/)
içindeki **Splunk Enterprise Security** hikâyesine nasıl bağlandığını açıklar.

> Bu bir Splunk entegrasyonu değildir. Amaç: JR olarak “olay üret → SIEM’e taşı → kural yaz”
> zincirini gösterebilmektir.

## Audit nasıl açılır?

```bash
python -m sifreleme_araci --audit-log audit.jsonl encrypt -t "x" -o x.bsa
# veya
set BSA_AUDIT_LOG=audit.jsonl
python -m sifreleme_araci decrypt -i x.bsa
```

Her satır bir JSON nesnesidir (JSONL).

## Ortak alanlar

| Alan | Anlam |
|---|---|
| `ts` | UTC zaman damgası |
| `event` | Sabit olay adı |
| `event_source` / `tool` / `vendor_product` | Kaynak kimliği |
| `version` | Araç sürümü |
| `auth_source` | `password` / `password_flag` / `keyfile` |

**Asla yazılmaz:** parola, keyfile içeriği, plaintext, ham PII.

## Olay kataloğu

| `event` | Ne zaman? | Splunk/SOC için fikir |
|---|---|---|
| `encrypt_ok` | Şifreleme başarılı | Normal operasyon |
| `encrypt_fail` | Şifreleme hata | Konfig / limit |
| `decrypt_ok` | Çözme başarılı | Erişim kaydı |
| `decrypt_fail` | Yanlış parola / bozulma | Brute-force adayı |
| `verify_ok` / `verify_fail` | Doğrulama | Integrity check |
| `scan_ok` | Keşif tamam | Discovery telemetrisi |
| `protect_ok` / `protect_fail` | Toplu koruma | Data protection job |
| `auth_source` | Secret kaynağı seçildi | password vs keyfile ayrımı |

## Örnek alert fikirleri (öğrenme)

### 1) Kısa sürede çok decrypt_fail

```text
index=* sourcetype=bsa_audit event=decrypt_fail
| bin _time span=5m
| stats count by host
| where count >= 10
```

Anlam: olası çevrimdışı/çevrimiçi kaba kuvvet veya bozuk paket denemesi.

### 2) Keyfile yerine password_flag kullanımı

```text
event=auth_source auth_source=password_flag
```

Anlam: demo anti-pattern; production’da azaltılmalı.

### 3) Protect job özeti

```text
event=protect_ok
| table ts protected_count finding_count output
```

## Örnek JSONL satırı

```json
{"ts":"2026-08-03T19:00:00Z","event":"decrypt_fail","event_source":"sifreleme_araci","tool":"sifreleme_araci","version":"1.3.0","vendor_product":"basit_sifreleme_araci","input":"not.bsa","error_type":"AuthenticationError"}
```

## Sınır

Kurumsal Splunk ES; UEBA, threat intel, correlation search ve risk scoring sunar.
Bu proje yalnızca **temiz, secrets’siz olay** üretir — SIEM’in ham maddesi.
