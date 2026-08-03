# Öğrenme Raporu — Aşama Aşama

**Proje:** Basit Şifreleme Aracı (v1.3)  
**Ne işe yarar bu belge?** Projede sırayla ne yapıldığını ve her adımda ne öğrenildiğini aktarır.  
**Ne değildir?** `report.md` yerine geçmez; kriptografi kararlarının uzun gerekçesi oradadır.

Kaynak bağlam: [Konsalt Güvenlik Çözümleri](https://www.konsalt.com.tr/cozumlerimiz/guvenlik-cozumleri/) (Voltage, Delinea, Splunk) — ürün klonu değil, öğrenme haritası.

---

## Aşama 1 — Temel şifreleme CLI

### Ne yaptık?

- `cryptography` ile **AES-256-GCM** (şifreleme + bütünlük) ve **Scrypt** (paroladan anahtar) kullandık.
- Kendi şifreleme algoritmamızı yazmadık.
- `encrypt` / `decrypt` komutlarını ve `cli` ↔ `crypto_ops` ayrımını kurduk.

### Ne öğrendik?

1. Güvenlik, algoritma icat etmek değil; **bilinen bileşenleri doğru birleştirmektir**.
2. Parola doğrudan AES anahtarı olmamalı; **KDF** (Scrypt) gerekir.
3. Yalnız gizlilik yetmez; **AEAD** (GCM) ile bütünlük de şarttır — manipüle paket sessizce açılmamalıdır.
4. Arayüz ile kriptografi katmanını ayırmak test etmeyi ve denetlemeyi kolaylaştırır.

---

## Aşama 2 — Paket formatı ve güvenli hata davranışı

### Ne yaptık?

- `.bsa` formatı: magic + sürüm + salt + nonce + ciphertext/tag.
- Format kimliğini GCM **AAD** ile bağladık.
- Yanlış parola / bozulmuş veri için **tek genel hata mesajı** verdik.
- `inspect` ve `verify` ekledik (içeriği açmadan bakma / doğrulama).

### Ne öğrendik?

1. Ham bayt yığını yetmez; **sürümlenebilir format** ileride migrasyon için gerekir.
2. Salt ve nonce her işlemde taze olmalı; aynı metin aynı ciphertext üretmemelidir.
3. “Parola mı yanlış, tag mi bozuk?” ayrımı saldırgana bilgi verebilir → **fail-closed + genelleştirilmiş mesaj**.
4. `inspect` içeriği açmamalıdır; aksi halde debug yolu sızıntı olur.

---

## Aşama 3 — Test, CI ve güvenli varsayılanlar

### Ne yaptık?

- Round-trip ve negatif testler (yanlış parola, tag bozma, kısa paket).
- CI: ruff, Bandit, pip-audit, Win/Linux test.
- Atomik yazma, mümkünse `0o600`, `getpass`, `BSA_MAX_BYTES`, `SECURITY.md`.

### Ne öğrendik?

1. Mutlu yol testi yetmez; güvenlik **negatif senaryolarla** kilitlenir.
2. Bağımlılık ve SAST taraması, “kodum doğru” kadar **tedarik zinciri** riskini de hedefler.
3. `--password` kolaydır ama process listesinde görünür; varsayılan yol **gizli giriş** olmalıdır.
4. Sınırları dürüst yazmak (KMS/HSM yok vb.) abartılı iddiadan daha güvenilirdir.

---

## Aşama 4 — Hassas veri keşfi ve koruma (`scan` / `protect`)

Konsalt tarafındaki karşılık fikri: **OpenText Voltage** (önce keşfet, sonra koru).

### Ne yaptık?

- `discovery.py`: e-posta, IBAN, telefon, kart, TCKN benzeri pattern’ler.
- Bulguları **maskeleyerek** raporladık; ham PII’yi log’a yazmadık.
- `protect`: bulgulu dosyaları `.bsa` yaptı; `--dry-run` ile önce plan gösterdik.
- Sentetik örnek set: `ornekler/hassas_ornek/`.

### Ne öğrendik?

1. Dosyayı şifrelemek tek başına “veri güvenliği ürünü” değildir; çoğu zaman önce **keşif** gelir.
2. Regex keşfi eğitim için yeterlidir ama **false positive** üretir (ör. IBAN içindeki rakamlar kart sanılabilir) — üretim DLP daha sıkı doğrular.
3. Raporda maskeleme, keşif aracının kendisinin sızıntı kaynağı olmasını engeller.
4. Toplu yazmadan önce **dry-run**, operasyonel hatayı azaltır.

```bash
python -m sifreleme_araci scan -i ornekler/hassas_ornek
python -m sifreleme_araci protect -i ornekler/hassas_ornek -o out --dry-run
```

---

## Aşama 5 — Denetim kaydı ve SIEM düşüncesi

Konsalt tarafındaki karşılık fikri: **Splunk ES** (olay topla → ilişkilendir → alert).

### Ne yaptık?

- `--audit-log` / `BSA_AUDIT_LOG` ile JSONL olaylar (`encrypt_ok`, `decrypt_fail`, `scan_ok`, …).
- Parola, key, plaintext, ham PII alanlarını yasakladık.
- `docs/siem-mapping.md` ile olay sözlüğü ve örnek alert fikirleri yazdık.

### Ne öğrendik?

1. SIEM şifrelemez; **temiz telemetri** ister.
2. Olay adları rastgele olmamalı; sabit bir **sözleşme** gibi tutulmalıdır.
3. Log’a secret yazmak, güvenlik kontrolünü güvenlik açığına çevirir.
4. Örnek: kısa sürede çok `decrypt_fail` → kaba kuvvet / bozuk paket hipotezi (alert fikri).

```bash
python -m sifreleme_araci --audit-log audit.jsonl scan -i ornekler/hassas_ornek --summary
```

---

## Aşama 6 — Secret kaynağını ayırma (`--keyfile`)

Konsalt tarafındaki karşılık fikri: **Delinea PAM** (hesap/secret yönetimi; vault).

### Ne yaptık?

- `secrets_io.py`: keyfile’dan secret okuma; `--password` ile birlikte kullanım yasağı.
- Encrypt / decrypt / verify / protect’te `--keyfile` desteği.
- Örnek dosya: `ornekler/vault.key.example`.
- Audit’te `auth_source` (`password` / `keyfile` / `password_flag`).

### Ne öğrendik?

1. **Dosya şifreleme** ile **ayrıcalıklı erişim / vault** aynı şey değildir.
2. Keyfile, “daha güçlü AES” demek değildir; **anahtarın nereden geldiğini** ayırır (vault metaforu).
3. Vault’un asıl değeri rotate / onay / oturum kaydı gibidir; tek satırlık secret dosyası bunu taklit etmez, yalnızca fikri gösterir.
4. Secret’ı komut satırına yazmamak, temel operasyonel güvenlik kuralıdır.

```bash
python -m sifreleme_araci encrypt -t "gizli" -o not.bsa --keyfile ornekler/vault.key.example
```

---

## Aşama 7 — Dokümantasyon, test ve kapsam sınırı

### Ne yaptık?

- `docs/konsalt-guvenlik-haritasi.md` — üç ürün ↔ proje karşılıkları.
- `tests/test_discovery_protect.py` — scan / protect / keyfile / audit’te PII yok.
- Sürüm `1.3.0`, demo akışına yeni adımlar.

### Ne öğrendik?

1. Özellik, test ve kısa doküman olmadan başkasına aktarılamaz.
2. Her yeni komut yeni risk açar (`scan` gürültüsü, `protect` toplu yazma); kapsam bilinçli dar tutulmalıdır.
3. Öğrenme projesinde ürün klonu yazmak gerekmez; **doğru sorumluluk ayrımı** yeterlidir.

### Bilinçli eklemediklerimiz

| Eklenmedi | Sebep |
|---|---|
| Mini Voltage / Delinea / Splunk | Kapsam dışı; öğrenme metaforu yeterli |
| KMS / HSM | Kurumsal altyapı; bu CLI’nin işi değil |
| GUI | Odak CLI ve güvenlik kararları |
| Argon2 / stream AEAD | Ayrı tasarım ve format sürümü ister |

---

## Özet

| Aşama | Yapılan | Öğrenilen (tek cümle) |
|---|---|---|
| 1 | AES-GCM + Scrypt CLI | Standart primitive doğru birleştirilir |
| 2 | Format + fail-closed | Bütünlük ve hata mesajı da tasarımdır |
| 3 | Test + CI + secure defaults | Negatif test ve güvenli varsayılan şart |
| 4 | `scan` / `protect` | Önce keşfet, sonra koru |
| 5 | Audit JSONL | SIEM temiz olay ister; secret log’a girmez |
| 6 | `--keyfile` | Vault/PAM ile şifreleme farklı katmanlardır |
| 7 | Harita + test | Kapsam kontrolü ve aktarılabilir doküman |

---

## İlgili dosyalar

- Teknik tasarım: [`report.md`](./report.md)
- Portföy haritası: [`docs/konsalt-guvenlik-haritasi.md`](./docs/konsalt-guvenlik-haritasi.md)
- SIEM sözlüğü: [`docs/siem-mapping.md`](./docs/siem-mapping.md)
- Güvenlik politikası: [`SECURITY.md`](./SECURITY.md)
