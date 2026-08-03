# Örnek hassas veri seti (SAHTE — eğitim amaçlı)

Bu klasördeki CSV/TXT dosyaları **sentetik** örnekler içerir.
Gerçek TCKN / IBAN / kart kullanmayın.

| Dosya | İçerik |
|---|---|
| `musteriler.csv` | E-posta, telefon, IBAN satırları |
| `notlar.txt` | E-posta, test kartı, sentetik kimlik |
| `temiz.txt` | Bilerek hassas pattern yok |

Keşif:

```bash
python -m sifreleme_araci scan -i ornekler/hassas_ornek
```
