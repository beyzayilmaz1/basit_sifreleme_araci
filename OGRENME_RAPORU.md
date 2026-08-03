# Öğrenme Raporu

**Proje:** Basit Şifreleme Aracı  
**Sürüm:** 1.3.0  
**Doküman türü:** Aşama aşama geliştirme ve öğrenme kaydı  
**Hedef okuyucu:** Staj / bonus değerlendirmesi yapan teknik yönetici  

Bu belge, projenin hangi sırayla genişletildiğini ve her aşamada hangi güvenlik fikrinin pekiştirildiğini özetler. Kriptografi kararlarının ayrıntılı gerekçesi [`report.md`](./report.md) içindedir; bu dosya onun yerine geçmez.

Kaynak bağlam: [Konsalt Güvenlik Çözümleri](https://www.konsalt.com.tr/cozumlerimiz/guvenlik-cozumleri/) (OpenText Voltage, Delinea, Splunk ES). Amaç ürün klonu üretmek değil; kurumsal güvenlik sorumluluklarını küçük, doğrulanabilir CLI parçalarına ayırarak öğrenmektir.

---

## Aşama 1 — Temel şifreleme CLI

### Yapılanlar

- `cryptography` kütüphanesi üzerinden **AES-256-GCM** (gizlilik + bütünlük) ve **Scrypt** (paroladan anahtar türetme) kullanıldı.
- Özel şifreleme algoritması yazılmadı.
- `encrypt` / `decrypt` komutları ile `cli` ↔ `crypto_ops` katman ayrımı kuruldu.

### Öğrenilenler

1. Güvenlik, algoritma icat etmek değil; **bilinen bileşenleri doğru birleştirmektir**.
2. Parola doğrudan AES anahtarı olmamalıdır; **KDF** (Scrypt) gerekir.
3. Yalnızca gizlilik yetmez; **AEAD** (GCM) ile bütünlük de sağlanmalıdır — manipüle paket sessizce açılmamalıdır.
4. Arayüz ile kriptografi katmanını ayırmak test ve denetimi kolaylaştırır.

---

## Aşama 2 — Paket formatı ve güvenli hata davranışı

### Yapılanlar

- `.bsa` (BSA1) formatı tanımlandı: magic + sürüm + salt + nonce + ciphertext/tag.
- Format kimliği GCM **AAD** ile ciphertext’e bağlandı.
- Yanlış parola ve bozulmuş veri için **tek genel hata mesajı** uygulandı.
- `inspect` ve `verify` komutları eklendi (içeriği açmadan inceleme / doğrulama).

### Öğrenilenler

1. Ham bayt yığını yetmez; **sürümlenebilir format** ileride migrasyon için gerekir.
2. Salt ve nonce her işlemde taze üretilmelidir; aynı metin aynı ciphertext üretmemelidir.
3. “Parola mı yanlış, tag mi bozuk?” ayrımı saldırgana bilgi verebilir → **fail-closed** ve genelleştirilmiş mesaj tercih edilir.
4. `inspect` içeriği açmamalıdır; aksi halde debug yolu sızıntı kaynağı olur.

---

## Aşama 3 — Test, CI ve güvenli varsayılanlar

### Yapılanlar

- Round-trip ve negatif testler yazıldı (yanlış parola, tag bozma, kısa paket, format hataları).
- CI hattı kuruldu: ruff, Bandit, pip-audit, Windows/Linux test.
- Atomik yazma, mümkünse `0o600` dosya izni, varsayılan `getpass`, `BSA_MAX_BYTES` limiti ve `SECURITY.md` (CVD) eklendi.

### Öğrenilenler

1. Mutlu yol testi yetmez; güvenlik sözleşmeleri **negatif senaryolarla** kilitlenir.
2. Bağımlılık ve SAST taraması, kod doğruluğunun yanı sıra **tedarik zinciri** riskini de hedefler.
3. `--password` kolaydır ancak process listesinde görünür; varsayılan yol **gizli giriş** olmalıdır.
4. Sınırları dürüst yazmak (KMS/HSM yok vb.) abartılı iddiadan daha güvenilirdir.

---

## Aşama 4 — Hassas veri keşfi ve koruma (`scan` / `protect`)

**Kurumsal karşılık (öğrenme metaforu):** OpenText Voltage — önce keşfet, sonra koru.

### Yapılanlar

- `discovery.py`: e-posta, IBAN, telefon, kart numarası ve TCKN benzeri desenler.
- Bulgular **maskelenerek** raporlandı; ham PII log’a yazılmadı.
- `protect`: bulgulu dosyaları `.bsa` paketlerine dönüştürdü; `--dry-run` ile önce plan gösterildi.
- Sentetik örnek veri seti: `ornekler/hassas_ornek/`.

### Öğrenilenler

1. Dosyayı şifrelemek tek başına “veri güvenliği ürünü” oluşturmaz; çoğu zaman önce **keşif** gelir.
2. Regex tabanlı keşif eğitim için yeterlidir; **false positive** üretebilir — üretim DLP daha sıkı doğrular.
3. Raporda maskeleme, keşif aracının kendisinin sızıntı kaynağı olmasını engeller.
4. Toplu yazmadan önce **dry-run**, operasyonel hatayı azaltır.

```bash
python -m sifreleme_araci scan -i ornekler/hassas_ornek
python -m sifreleme_araci protect -i ornekler/hassas_ornek -o out --dry-run
```

---

## Aşama 5 — Denetim kaydı ve SIEM düşüncesi

**Kurumsal karşılık (öğrenme metaforu):** Splunk Enterprise Security — olay topla, ilişkilendir, alert üret.

### Yapılanlar

- `--audit-log` / `BSA_AUDIT_LOG` ile JSONL olaylar (`encrypt_ok`, `decrypt_fail`, `scan_ok`, …).
- Parola, anahtar, plaintext ve ham PII alanları yasaklandı.
- `docs/siem-mapping.md` ile olay sözlüğü ve örnek alert fikirleri belgelendi.

### Öğrenilenler

1. SIEM şifrelemez; **temiz telemetri** ister.
2. Olay adları rastgele olmamalı; sabit bir **sözleşme** gibi tutulmalıdır.
3. Log’a secret yazmak, güvenlik kontrolünü güvenlik açığına çevirir.
4. Kısa sürede çok sayıda `decrypt_fail`, kaba kuvvet veya bozuk paket hipotezini destekleyebilir (alert fikri).

```bash
python -m sifreleme_araci --audit-log audit.jsonl scan -i ornekler/hassas_ornek --summary
```

---

## Aşama 6 — Secret kaynağını ayırma (`--keyfile`)

**Kurumsal karşılık (öğrenme metaforu):** Delinea PAM — hesap/secret yönetimi (vault).

### Yapılanlar

- `secrets_io.py`: keyfile’dan secret okuma; `--password` ile birlikte kullanım yasağı.
- `encrypt` / `decrypt` / `verify` / `protect` komutlarında `--keyfile` desteği.
- Örnek dosya: `ornekler/vault.key.example`.
- Audit’te `auth_source` alanı (`password` / `keyfile` / `password_flag`).

### Öğrenilenler

1. **Dosya şifreleme** ile **ayrıcalıklı erişim / vault** aynı katman değildir.
2. Keyfile “daha güçlü AES” demek değildir; **anahtarın nereden geldiğini** ayırır (vault metaforu).
3. Vault’un asıl değeri rotate, onay ve oturum kaydıdır; tek satırlık secret dosyası bunu taklit etmez, yalnızca fikri gösterir.
4. Secret’ı komut satırına yazmamak temel operasyonel güvenlik kuralıdır.

```bash
python -m sifreleme_araci encrypt -t "gizli" -o not.bsa --keyfile ornekler/vault.key.example
```

---

## Aşama 7 — Dokümantasyon, test ve kapsam sınırı

### Yapılanlar

- `docs/konsalt-guvenlik-haritasi.md` — üç ürün ile proje karşılıkları.
- `tests/test_discovery_protect.py` — scan / protect / keyfile / audit’te PII yok kontrolleri.
- Sürüm `1.3.0`; demo akışına yeni adımlar eklendi.
- Teknik rapor (`report.md`) ve güvenlik politikası (`SECURITY.md`) v1.3 ile hizalandı.

### Öğrenilenler

1. Özellik; test ve kısa doküman olmadan başkasına aktarılamaz.
2. Her yeni komut yeni risk açar (`scan` gürültüsü, `protect` toplu yazma); kapsam bilinçli dar tutulmalıdır.
3. Öğrenme projesinde ürün klonu yazmak gerekmez; **doğru sorumluluk ayrımı** yeterlidir.

### Bilinçli olarak eklenmeyenler

| Eklenmedi | Gerekçe |
|---|---|
| Mini Voltage / Delinea / Splunk ürünü | Kapsam dışı; öğrenme metaforu yeterli |
| KMS / HSM | Kurumsal altyapı; bu CLI’nin işi değil |
| Grafik arayüz | Odak CLI ve güvenlik kararları |
| Argon2id / akışlı (stream) AEAD | Ayrı tasarım ve format sürümü ister |
| Gerçek PAM (oturum kaydı, onay akışı) | Keyfile yalnızca secret kaynağı metaforudur |

---

## Özet tablo

| Aşama | Yapılan | Öğrenilen (özet) |
|---|---|---|
| 1 | AES-GCM + Scrypt CLI | Standart primitive doğru birleştirilir |
| 2 | Format + fail-closed | Bütünlük ve hata mesajı da tasarımdır |
| 3 | Test + CI + secure defaults | Negatif test ve güvenli varsayılan şarttır |
| 4 | `scan` / `protect` | Önce keşfet, sonra koru |
| 5 | Audit JSONL | SIEM temiz olay ister; secret log’a girmez |
| 6 | `--keyfile` | Vault/PAM ile şifreleme farklı katmanlardır |
| 7 | Harita + test + doküman | Kapsam kontrolü ve aktarılabilir belgeleme |

---

## İlgili dosyalar

| Dosya | İçerik |
|---|---|
| [`report.md`](./report.md) | Teknik tasarım, threat model, OWASP eşlemesi |
| [`docs/konsalt-guvenlik-haritasi.md`](./docs/konsalt-guvenlik-haritasi.md) | Konsalt ürün ↔ proje karşılıkları |
| [`docs/siem-mapping.md`](./docs/siem-mapping.md) | Audit olay sözlüğü ve örnek alert fikirleri |
| [`SECURITY.md`](./SECURITY.md) | CVD / güvenlik politikası ve kontrol eşlemesi |
| [`README.md`](./README.md) | Kurulum, kullanım, özellik özeti |
