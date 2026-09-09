# RESCAT - Fidye Yazılımı Analiz ve Şifre Çözücü Paketi

[English](README_EN.md) | [Türkçe](README.md)

```
  ██████╗ ███████╗███████╗ ██████╗ █████╗ ████████╗
  ██╔══██╗██╔════╝██╔════╝██╔════╝██╔══██╗╚══██╔══╝
  ██████╔╝█████╗  ███████╗██║     ███████║   ██║   
  ██╔══██╗██╔══╝  ╚════██║██║     ██╔══██║   ██║   
  ██║  ██║███████╗███████║╚██████╗██║  ██║   ██║   
  ╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   
```

Modern fidye yazılımları (LockBit, Akira, BlackCat, Babuk, ESXiArgs, STOP/Djvu vb.) ve şifrelenmiş dosyalar üzerinde adli analiz, algoritma tespiti, bellekten anahtar çıkarma ve şifre çözümü gerçekleştiren, %100 çevrim dışı (air-gapped) çalışan bir olay müdahale (DFIR) ve kriptanaliz aracıdır.

---

## Özellikler

| Özellik | Açıklama |
|---|---|
| %100 Çevrim Dışı | Ağ bağlantısı gerektirmez; hiçbir veriyi veya anahtarı dışarı sızdırmaz. |
| Otonom Çözüm | Parametresiz tek komutla dosya türü tespiti, algoritma tayini ve veri kurtarma. |
| X25519 ve Hibrit ECDH | LockBit 3.0, Akira ve Babuk için geçici kamu anahtarı ve paylaşılan sır çözümü. |
| Sosemanuk Akış Şifresi | ESXiArgs ve Babuk sanal diskleri için eSTREAM Profile 1 çözücüsü. |
| Aralıklı (Intermittent) Şifreleme | Blok atlamalı şifrelenen dosyalardan sağlam açık metin sektörlerini kurtarma. |
| ESXi VMDK Onarımı | Başlığı silinmiş -flat.vmdk diskleri için tanımlayıcı (descriptor) üretimi. |
| Canlı Süreç Dondurucu | Çalışan fidye yazılımını anında durdurup (SIGSTOP) RAM dökümünü alma. |
| Crib-Dragging | Nonce tekrarı zaafiyeti üzerinden anahtarsız %100 açık metin kurtarma. |
| Çok Çekirdekli Kırıcı | Multiprocessing ve kural tabanlı mutasyonla paralel sözlük saldırısı. |
| 35+ Format ve Ki-Kare | Veritabanı ve tescilli ikili (binary) formatlar için yapısal bütünlük doğrulaması. |
| Adli Kurtarma (DFIR) | VSS gölge kopyaları, Btrfs/ZFS anlık görüntüleri ve SQLite WAL kayıtlarını kurtarma. |
| RAM Anahtar Avcısı | Bellek dökümünden AES-128/256, ChaCha20, Salsa20 ve RSA anahtarlarını çekme. |

---

## Kurulum

```bash
git clone https://github.com/erensogutlu/rescat.git
cd rescat
pip install -r requirements.txt
pip install -e .
```

Sistem Gereksinimi: Python 3.8 veya üzeri (Linux / Windows)

---

## Hızlı Kullanım

### 1. Otonom Dizin Taraması ve Şifre Çözümü
```bash
sudo rescat genel-tarama /hedef/vaka_dizini/
```

### 2. Tekil Dosya Kurtarma
```bash
sudo rescat ozel-tarama /hedef/belge.pdf.locked
```

### 3. Canlı Fidye Sürecini Dondurma ve RAM Dökümü Alma
```bash
# Çalışan şüpheli süreçleri tara ve listele:
sudo rescat canli-avci --tara

# Belirtilen süreci anında dondur ve belleğini diske aktar:
sudo rescat canli-avci --pid <PID> --dokum /tmp/ram.dmp
```

### 4. RAM Dökümünden Anahtar Çıkarma
```bash
rescat avci /tmp/ram.dmp
```

### 5. ESXi VMDK Rekonstrüksiyonu
```bash
sudo rescat vmdk-kurtar /sanaldizin/sunucu-flat.vmdk --cikti /kurtarma_dizini/
```

### 6. Nonce Tekrarı ile Anahtarsız Çözüm (Crib-Dragging)
```bash
rescat crib-drag dosya1.pdf.enc dosya2.png.enc
```

### 7. Adli Kurtarma (Gölge Kopya, Snapshot, SQLite WAL)
```bash
sudo rescat adli-kurtar /hedef/vaka_dizini/
```

### 8. Etkileşimli Terminal Rehberi
```bash
sudo python3 rescat.py
```

---

## Komut Referansı

| Komut | Açıklama |
|---|---|
| rescat genel-tarama [DİZİN] | Dizin genelinde otomatik tarama ve şifre çözümü |
| rescat ozel-tarama DOSYA | Belirli bir dosyaya odaklı derinlemesine analiz ve çözüm |
| rescat analiz HEDEF | Entropi haritalaması ve algoritma imza analizi |
| rescat coz HEDEF | Doğrudan dosya çözme (--algoritma, --anahtar) |
| rescat otonom HEDEF | Harici müdahale gerektirmeyen tam otonom kurtarma |
| rescat canli-avci | Çalışan süreci dondurma (SIGSTOP) ve RAM alma |
| rescat avci DÖKÜM | RAM dökümünden AES, X25519, ChaCha ve RSA anahtarlarını avlama |
| rescat chacha-avci DÖKÜM | Bellekten ChaCha20/Salsa20 durum matrisi arama |
| rescat vmdk-kurtar DOSYA | ESXi sanal disk bölüntü ve tanımlayıcı (descriptor) onarımı |
| rescat crib-drag D1 D2 | Nonce tekrarı durumunda anahtarsız iki dosya çözümü |
| rescat aralikli DOSYA | Blok atlamalı şifreleme analizi ve açık sektör kurtarma |
| rescat adli-kurtar HEDEF | VSS, Snapshot, SQLite WAL ve geçici dosya kurtarma |
| rescat kpa --orijinal .. --sifreli .. | Bilinen Düz Metin Saldırısı (KPA) ile XOR anahtarı çözme |
| rescat zaman-kirici DOSYA | Zaman tabanlı zayıf PRNG tohum kırma |
| rescat zayif-rsa -n .. -e .. | Zayıf RSA faktörizasyonu (Fermat ve Wiener) |
| rescat yapisal-kurtar DOSYA | Kısmi şifreli ZIP, SQLite ve PDF onarımı |
| rescat keystream D1 D2 | Keystream analizi ve açık metin çıkarma |
| rescat onar DOSYA --format .. | Hasarlı dosya başlıklarını yamayarak onarma |
| rescat interaktif | İki seçenekli rehber sihirbazı başlat |

---

## Proje Yapısı

```
rescat/
├── rescat.py                  # CLI ana giriş çalıştırıcısı
├── pyproject.toml             # Paketleme ve dağıtım ayarları
├── requirements.txt           # Bağımlılık listesi
├── README.md                  # Türkçe dokümantasyon
├── README_EN.md               # İngilizce dokümantasyon
├── SECURITY.md                # Güvenlik açığı bildirme politikası
├── CONTRIBUTING.md            # Topluluk katkı kılavuzu
├── CHANGELOG.md               # Sürüm ve değişiklik geçmişi
├── .github/workflows/ci.yml   # GitHub Actions CI test iş akışı
├── rescat/
│   ├── ana_komut.py           # 21 alt komutlu CLI yöneticisi
│   ├── otonom.py              # Otonom adli analiz ve kurtarma motoru
│   ├── analizciler/           # Bellek, canlı süreç ve adli kurtarma modülleri
│   ├── cekirdek/              # Kriptografik analiz ve kırma motorları
│   ├── cozuculer/             # Şifre çözme algoritmaları
│   └── yardimcilar/           # TUI, konsol ve raporlama bileşenleri
```

---

## Yasal Uyarı

Bu araç yalnızca yetkili adli bilişim incelemeleri, DFIR olay müdahale süreçleri ve mağdurların kendi verilerini kurtarmaları amacıyla geliştirilmiştir. İzin alınmamış sistemler üzerinde kullanılması yasalara aykırıdır. Kötüye kullanım durumunda tüm sorumluluk kullanıcıya aittir.

---

Geliştirici: Eren Söğütlü
Sürüm: 1.0.0
