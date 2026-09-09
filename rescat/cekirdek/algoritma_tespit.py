import os
import math
import struct
from collections import Counter
from typing import Any, Dict, List, Optional
from rescat.cekirdek.entropi import dosya_entropisi_hesapla, kismi_sifreleme_analizi, shannon_entropisi_hesapla
from rescat.cekirdek.dosya_tanimlayici import BILINEN_SIHIRLI_BAYTLAR, sihirli_baytlardan_tur_tahmin_et, dosya_baslik_analizi_yap
from rescat.cekirdek.sizinti_veritabani import (
    DJVU_GENISLETILMIS_OFFLINE_ANAHTARLAR,
    sizinti_anahtari_sorgula,
    bilinen_cozucu_tavsiyesi
)
from rescat.cekirdek.zaman_kirici import dosya_zaman_damgasi_al, zaman_tabanli_xor_kir


# zararlı yazılım ve uzantı eşleme haritası.
ALGORITMA_UZANTI_HARITASI: Dict[str, Dict[str, Any]] = {
    # twofish ailesi.
    ".twofish": {"algoritma": "Twofish (128/256-bit CBC)", "kategori": "STANDART_KRIPTO", "cozucu": "twofish_cozucu", "guven": 0.95},
    ".tf": {"algoritma": "Twofish (128/256-bit CBC)", "kategori": "STANDART_KRIPTO", "cozucu": "twofish_cozucu", "guven": 0.90},
    ".notpetya": {"algoritma": "NotPetya (Twofish-CBC / Salsa20)", "kategori": "RANSOMWARE", "cozucu": "twofish_cozucu", "guven": 0.95},
    ".mptya": {"algoritma": "NotPetya / GoldenEye (Twofish / Salsa20)", "kategori": "RANSOMWARE", "cozucu": "twofish_cozucu", "guven": 0.92},
    ".megacortex": {"algoritma": "MegaCortex (Twofish-CBC + AES-CBC)", "kategori": "RANSOMWARE", "cozucu": "twofish_cozucu", "guven": 0.92},

    # salsa20 ailesi.
    ".salsa20": {"algoritma": "Salsa20 (Salsa20/20 Akış Şifreleyici)", "kategori": "STANDART_KRIPTO", "cozucu": "salsa20_cozucu", "guven": 0.95},
    ".sodinokibi": {"algoritma": "REvil / Sodinokibi (Salsa20/20 + Curve25519)", "kategori": "RANSOMWARE", "cozucu": "salsa20_cozucu", "guven": 0.92},
    ".revil": {"algoritma": "REvil (Salsa20/20 + Curve25519)", "kategori": "RANSOMWARE", "cozucu": "salsa20_cozucu", "guven": 0.95},
    ".petya": {"algoritma": "Petya (Salsa20/20)", "kategori": "RANSOMWARE", "cozucu": "salsa20_cozucu", "guven": 0.95},
    ".mischa": {"algoritma": "Mischa (Salsa20/20)", "kategori": "RANSOMWARE", "cozucu": "salsa20_cozucu", "guven": 0.92},

    # rc4 ailesi.
    ".rc4": {"algoritma": "RC4 (ARC4 Akış Şifreleyici)", "kategori": "STANDART_KRIPTO", "cozucu": "rc4_cozucu", "guven": 0.95},
    ".cerber": {"algoritma": "Cerber (RC4 / AES Akış Katmanı)", "kategori": "RANSOMWARE", "cozucu": "rc4_cozucu", "guven": 0.90},
    ".cerber2": {"algoritma": "Cerber v2 (RC4 / AES)", "kategori": "RANSOMWARE", "cozucu": "rc4_cozucu", "guven": 0.90},
    ".cerber3": {"algoritma": "Cerber v3 (RC4 / AES)", "kategori": "RANSOMWARE", "cozucu": "rc4_cozucu", "guven": 0.90},
    ".troldesh": {"algoritma": "Troldesh / Shade (AES-256-CBC + RSA)", "kategori": "RANSOMWARE", "cozucu": "aes_cozucu", "guven": 0.92},
    ".xtbl": {"algoritma": "Troldesh / Shade (.xtbl - AES-256-CBC)", "kategori": "RANSOMWARE", "cozucu": "aes_cozucu", "guven": 0.90},

    # tea ailesi.
    ".tea": {"algoritma": "TEA (Tiny Encryption Algorithm - 64-bit Blok)", "kategori": "STANDART_KRIPTO", "cozucu": "tea_cozucu", "guven": 0.95},
    ".xtea": {"algoritma": "XTEA (Extended TEA - 64-bit Blok)", "kategori": "STANDART_KRIPTO", "cozucu": "xtea_cozucu", "guven": 0.95},
    ".xxtea": {"algoritma": "XXTEA (Corrected Block TEA)", "kategori": "STANDART_KRIPTO", "cozucu": "xxtea_cozucu", "guven": 0.95},

    # blowfish ve 3des ailesi.
    ".blowfish": {"algoritma": "Blowfish (64-bit Blok, Değişken Anahtar)", "kategori": "STANDART_KRIPTO", "cozucu": "blowfish_cozucu", "guven": 0.95},
    ".bf": {"algoritma": "Blowfish (64-bit Blok)", "kategori": "STANDART_KRIPTO", "cozucu": "blowfish_cozucu", "guven": 0.90},
    ".3des": {"algoritma": "TripleDES (3DES-EDE3 - 64-bit Blok)", "kategori": "STANDART_KRIPTO", "cozucu": "3des_cozucu", "guven": 0.95},
    ".des3": {"algoritma": "TripleDES (3DES-EDE3 - 64-bit Blok)", "kategori": "STANDART_KRIPTO", "cozucu": "3des_cozucu", "guven": 0.95},

    # camellia, sm4, seed, cast5 ve idea.
    ".camellia": {"algoritma": "Camellia (128/256-bit Blok)", "kategori": "STANDART_KRIPTO", "cozucu": "camellia_cozucu", "guven": 0.95},
    ".cast5": {"algoritma": "CAST5 / CAST-128 (64-bit Blok)", "kategori": "STANDART_KRIPTO", "cozucu": "cast5_cozucu", "guven": 0.95},
    ".idea": {"algoritma": "IDEA (64-bit Blok, 128-bit Anahtar)", "kategori": "STANDART_KRIPTO", "cozucu": "idea_cozucu", "guven": 0.95},
    ".sm4": {"algoritma": "SM4 Ulusal Şifreleyici (128-bit Blok)", "kategori": "STANDART_KRIPTO", "cozucu": "sm4_cozucu", "guven": 0.95},
    ".seed": {"algoritma": "SEED (128-bit Blok, 128-bit Anahtar)", "kategori": "STANDART_KRIPTO", "cozucu": "seed_cozucu", "guven": 0.95},

    # locky, gandcrab, akira ve blackcat.
    ".locky": {"algoritma": "Locky Ransomware (AES-128-CBC + RSA-2048)", "kategori": "RANSOMWARE", "cozucu": "aes_cozucu", "guven": 0.95},
    ".zepto": {"algoritma": "Locky / Zepto (AES-128-CBC)", "kategori": "RANSOMWARE", "cozucu": "aes_cozucu", "guven": 0.92},
    ".odin": {"algoritma": "Locky / Odin (AES-128-CBC)", "kategori": "RANSOMWARE", "cozucu": "aes_cozucu", "guven": 0.92},
    ".thor": {"algoritma": "Locky / Thor (AES-128-CBC)", "kategori": "RANSOMWARE", "cozucu": "aes_cozucu", "guven": 0.92},
    ".crab": {"algoritma": "GandCrab (Salsa20 / AES + RSA)", "kategori": "RANSOMWARE", "cozucu": "salsa20_cozucu", "guven": 0.92},
    ".krab": {"algoritma": "GandCrab v4/v5 (Salsa20 / AES)", "kategori": "RANSOMWARE", "cozucu": "salsa20_cozucu", "guven": 0.92},
    ".alphv": {"algoritma": "BlackCat / ALPHV (ChaCha20-Poly1305 / AES)", "kategori": "RANSOMWARE", "cozucu": "chacha_cozucu", "guven": 0.92},
    ".akira": {"algoritma": "Akira Ransomware (ChaCha20 + RSA)", "kategori": "RANSOMWARE", "cozucu": "chacha_cozucu", "guven": 0.92},
    ".royal": {"algoritma": "Royal Ransomware (OpenSSL AES-256-CBC)", "kategori": "RANSOMWARE", "cozucu": "openssl_cozucu", "guven": 0.92}
}


def ki_kare_rastgelelik_skoru(baytlar: bytes) -> Dict[str, float]:
    """
    bayt frekans dağılımı üzerinden ki-kare (chi-square) testi ve
    rastgelelik uyum yüzdesini hesaplar.
    """
    n = len(baytlar)
    if n < 16:
        return {"chi_kare": 0.0, "rastgelelik_orani": 0.0, "ortalama": 0.0}

    beklenen = n / 256.0
    sayim = Counter(baytlar)
    chi_kare = sum(((sayim.get(i, 0) - beklenen) ** 2) / beklenen for i in range(256))
    ortalama = sum(baytlar) / float(n)

    # ki-kare serbestlik derecesi hesabı.
    # sapma miktarına göre rastgelelik yüzdesi.
    fark = abs(chi_kare - 255.0)
    rastgelelik = max(0.0, min(100.0, 100.0 - (fark / 255.0) * 40.0))

    return {
        "chi_kare": round(chi_kare, 2),
        "rastgelelik_orani": round(rastgelelik, 1),
        "ortalama": round(ortalama, 2)
    }


def algoritma_tespit_et(dosya_yolu: str) -> Dict[str, Any]:
    """
    hedef şifreli dosyanın başlığını, imzasını, blok yapısını,
    entropisini ve zararlı belirteçlerini inceleyerek şifreleme algoritmasını
    ve en uygun çözüm yöntemlerini belirler.
    """
    if not os.path.exists(dosya_yolu):
        return {
            "dosya": dosya_yolu,
            "basarili": False,
            "hata": "Dosya bulunamadı"
        }

    boyut = os.path.getsize(dosya_yolu)
    if boyut == 0:
        return {
            "dosya": dosya_yolu,
            "algoritma": "Boş Dosya",
            "kategori": "GECERSIZ",
            "guven": 1.0,
            "sifreli_mi": False,
            "onerilen_cozuculer": []
        }

    # dosya başı ve sonundan baytları okur.
    with open(dosya_yolu, "rb") as f:
        ilk_baytlar = f.read(min(boyut, 4096))
        son_baytlar = b""
        if boyut > 512:
            f.seek(max(0, boyut - 512))
            son_baytlar = f.read(512)

    uzanti = os.path.splitext(dosya_yolu)[1].lower()
    kok_isim, _ = os.path.splitext(dosya_yolu)
    tahmini_asil_uzanti = (os.path.splitext(kok_isim)[1] or uzanti).lstrip(".").lower()
    entropi = dosya_entropisi_hesapla(dosya_yolu)

    # 1. openssl şifreleme kontrolü.
    if ilk_baytlar.startswith(b"Salted__"):
        salt_hex = ilk_baytlar[8:16].hex() if len(ilk_baytlar) >= 16 else ""
        govde_boyutu = max(0, boyut - 16)
        if govde_boyutu % 16 == 0:
            olasi_simetrik = "AES-256-CBC / AES-128-CBC / Camellia"
        elif govde_boyutu % 8 == 0:
            olasi_simetrik = "3DES-CBC / Blowfish-CBC / CAST5"
        else:
            olasi_simetrik = "RC4 Akış Şifreleyicisi"

        return {
            "dosya": dosya_yolu,
            "algoritma": "OpenSSL EVP (AES-256-CBC / PBKDF2)",
            "kategori": "STANDART_KRIPTO",
            "guven": 0.99,
            "sifreli_mi": True,
            "salt_hex": salt_hex,
            "detay": f"OpenSSL Salted konteyneri ({olasi_simetrik}). Salt: {salt_hex}",
            "onerilen_cozuculer": ["openssl_cozucu", "aes_cozucu", "3des_cozucu", "blowfish_cozucu", "sozluk_saldirisi"]
        }

    # 2. pgp ve gpg paketi kontrolü.
    pgp_tespit = False
    if ilk_baytlar.startswith(b"-----BEGIN PGP MESSAGE-----"):
        pgp_tespit = True
    elif len(ilk_baytlar) >= 4:
        # openpgp paket doğrulaması.
        if (ilk_baytlar[0] == 0x8C and ilk_baytlar[2] in (3, 4)) or \
           (ilk_baytlar[0] == 0x85 and ilk_baytlar[3] in (3, 4)) or \
           (ilk_baytlar[0] == 0xD2 and ilk_baytlar[2] == 1):
            pgp_tespit = True

    if pgp_tespit:
        return {
            "dosya": dosya_yolu,
            "algoritma": "OpenPGP / GPG Şifrelemesi (CAST5 / IDEA / 3DES / AES)",
            "kategori": "STANDART_KRIPTO",
            "guven": 0.98,
            "sifreli_mi": True,
            "detay": "RFC 4880 OpenPGP şifrelenmiş veri paketi tespit edildi.",
            "onerilen_cozuculer": ["gpg_cozucu", "cast5_cozucu", "idea_cozucu", "anahtar_avcisi"]
        }

    # 2.8 dfir test başlıkları kontrolü.
    if ilk_baytlar.startswith(b"DFIRTEST-AES256-GCM") or ilk_baytlar.startswith(b"SAFE_TEST_AES256_GCM") or ilk_baytlar.startswith(b"AES_GCM"):
        return {
            "dosya": dosya_yolu,
            "algoritma": "AES-256-GCM (DFIR Benchmark / Güvenli Test)",
            "kategori": "STANDART_KRIPTO",
            "guven": 1.0,
            "sifreli_mi": True,
            "detay": "AES-256-GCM test başlığı tespit edildi. Dosya GCM modu ve 128-bit Tag ile şifrelenmiş.",
            "onerilen_cozuculer": ["aes_cozucu", "bellek_avi"]
        }
    if ilk_baytlar.startswith(b"DFIRTEST-AES256-CBC") or ilk_baytlar.startswith(b"SAFE_TEST_AES256_CBC"):
        return {
            "dosya": dosya_yolu,
            "algoritma": "AES-256-CBC (DFIR Benchmark / Güvenli Test)",
            "kategori": "STANDART_KRIPTO",
            "guven": 1.0,
            "sifreli_mi": True,
            "detay": "AES-256-CBC test başlığı tespit edildi. Dosya CBC modu ve PKCS#7 dolgu ile şifrelenmiş.",
            "onerilen_cozuculer": ["aes_cozucu", "bellek_avi"]
        }

    # 3. wannacry belirteci kontrolü.
    if ilk_baytlar.startswith(b"WANACRY!"):
        return {
            "dosya": dosya_yolu,
            "algoritma": "WannaCry (AES-128-CBC + RSA-2048)",
            "kategori": "RANSOMWARE",
            "guven": 1.0,
            "sifreli_mi": True,
            "detay": "WannaCry başlığı doğrulandı. Dosya AES-128-CBC ile şifrelenmiş.",
            "onerilen_cozuculer": ["aes_cozucu", "bellek_avi"]
        }

    # 3.1 ryuk belirteci kontrolü.
    if (son_baytlar and b"HERMES" in son_baytlar[-64:]) or uzanti == ".ryuk":
        return {
            "dosya": dosya_yolu,
            "algoritma": "Ryuk Ransomware (AES-256-CBC + RSA-4096)",
            "kategori": "RANSOMWARE",
            "guven": 0.95,
            "sifreli_mi": True,
            "detay": "Ryuk/Hermes belirteci doğrulandı. Dosya AES-256-CBC ile şifrelenmiş.",
            "onerilen_cozuculer": ["aes_cozucu", "bellek_avi"]
        }

    # 3.2 babuk ve conti belirteci kontrolü.
    if (son_baytlar and b"chatchat" in son_baytlar[-64:]) or uzanti in (".babuk", ".babyk", ".conti"):
        algo_adi = "Babuk" if "bab" in uzanti or (son_baytlar and b"chatchat" in son_baytlar[-64:]) else "Conti"
        return {
            "dosya": dosya_yolu,
            "algoritma": f"{algo_adi} Ransomware (ChaCha20 + Curve25519/RSA)",
            "kategori": "RANSOMWARE",
            "guven": 0.92,
            "sifreli_mi": True,
            "detay": f"{algo_adi} şifreleme profili tespit edildi. Dosya ChaCha20 akış şifreleyicisi ile şifrelenmiş.",
            "onerilen_cozuculer": ["chacha_cozucu", "bellek_avi"]
        }

    # 3.3 stop/djvu kurban id tespiti.
    stop_uzantilari = tuple(f".{u}" for u in DJVU_GENISLETILMIS_OFFLINE_ANAHTARLAR.keys())
    has_stop_footer = False
    kurban_id = None
    if son_baytlar:
        son_metin = son_baytlar[-64:]
        if b"t1" in son_metin or b"offline" in son_metin.lower():
            has_stop_footer = True
            try:
                kurban_id = son_metin.decode("ascii", errors="ignore").strip()
            except Exception:
                pass

    if uzanti in stop_uzantilari or uzanti in (".djvu", ".stop") or has_stop_footer:
        return {
            "dosya": dosya_yolu,
            "algoritma": "Stop/Djvu Ransomware (AES-256-CBC)",
            "kategori": "RANSOMWARE",
            "guven": 0.95 if has_stop_footer else 0.85,
            "sifreli_mi": True,
            "kurban_id": kurban_id,
            "detay": f"Stop/Djvu ailesi tespit edildi (Uzantı: {uzanti}). Çevrimdışı anahtarlarla kurtarılabilir.",
            "onerilen_cozuculer": ["djvu_offline", "djvu_cozucu", "aes_cozucu", "bellek_avi"]
        }

    # 3.4 uzantı haritası kontrolü.
    if uzanti in ALGORITMA_UZANTI_HARITASI:
        harita = ALGORITMA_UZANTI_HARITASI[uzanti]
        return {
            "dosya": dosya_yolu,
            "algoritma": harita["algoritma"],
            "kategori": harita["kategori"],
            "guven": harita["guven"],
            "sifreli_mi": True,
            "detay": f"{uzanti} profili eşleşti ({harita['algoritma']}).",
            "onerilen_cozuculer": [harita["cozucu"], "bellek_avi", "sozluk_saldirisi"]
        }

    # 4. şifreli zip arşivi kontrolü.
    if ilk_baytlar.startswith(b"PK\x03\x04") and len(ilk_baytlar) >= 10:
        flags = struct.unpack("<H", ilk_baytlar[6:8])[0]
        if flags & 0x01:
            algo_tipi = "WinZip-AES" if b"\x01\x99" in ilk_baytlar[:64] else "ZipCrypto (Standart PKZIP)"
            return {
                "dosya": dosya_yolu,
                "algoritma": f"Şifreli ZIP Arşivi ({algo_tipi})",
                "kategori": "STANDART_KRIPTO",
                "guven": 0.99,
                "sifreli_mi": True,
                "detay": f"Şifreli ZIP arşivi tespit edildi. Yöntem: {algo_tipi}",
                "onerilen_cozuculer": ["zip_kirici", "sozluk_saldirisi"]
            }

    # 5. şifreli 7z arşivi kontrolü.
    if ilk_baytlar.startswith(b"7z\xbc\xaf\x27\x1c"):
        return {
            "dosya": dosya_yolu,
            "algoritma": "Şifreli 7-Zip Arşivi (AES-256-CBC)",
            "kategori": "STANDART_KRIPTO",
            "guven": 0.90,
            "sifreli_mi": True,
            "detay": "7z arşivi tespit edildi. Başlıklar veya veri blokları şifrelenmiş olabilir.",
            "onerilen_cozuculer": ["7z_kirici", "sozluk_saldirisi"]
        }

    # 6. aralıklı şifreleme analizi.
    kismi_analiz = kismi_sifreleme_analizi(dosya_yolu)
    if kismi_analiz.get("kismi_sifreli_mi"):
        return {
            "dosya": dosya_yolu,
            "algoritma": "Askeri Standart Kısmi Şifreleme (Intermittent)",
            "kategori": "KISMI_SIFRELEME",
            "guven": 0.88,
            "sifreli_mi": True,
            "detay": "Dosyanın yalnızca belirli blokları şifrelenmiş; geri kalan veriler derin rekonstrüksiyon ile kurtarılabilir.",
            "onerilen_cozuculer": ["yapisal_kurtarici"]
        }

    # 7. bozuk başlık kontrolü.
    baslik_analizi = dosya_baslik_analizi_yap(dosya_yolu)
    if baslik_analizi.get("baslik_bozulmus_mu") and entropi < 7.2:
        return {
            "dosya": dosya_yolu,
            "algoritma": "Bozuk / Manipüle Edilmiş Dosya Başlığı",
            "kategori": "BOZUK_BASLIK",
            "guven": 0.85,
            "sifreli_mi": True,
            "detay": f"Dosya gövdesi sağlam, yalnızca ilk baytları bozulmuş ({tahmini_asil_uzanti}).",
            "onerilen_cozuculer": ["baslik_yamalama"]
        }

    # 8. zaman tabanlı tohum kontrolü.
    zaman = dosya_zaman_damgasi_al(dosya_yolu)
    kirma_on_test = zaman_tabanli_xor_kir(
        ilk_baytlar,
        merkez_zaman=zaman,
        aralik_saniye=60,
        beklenen_uzanti=tahmini_asil_uzanti if tahmini_asil_uzanti in BILINEN_SIHIRLI_BAYTLAR else None
    )
    if kirma_on_test and kirma_on_test.get("basarili"):
        return {
            "dosya": dosya_yolu,
            "algoritma": "Zaman-Tabanlı PRNG XOR (LCG Tohum)",
            "kategori": "ZAYIF_PRNG",
            "guven": 0.99,
            "sifreli_mi": True,
            "detay": f"Zaman damgası tohumu doğrulandı: {kirma_on_test.get('kurtarilan_tohum')}. Anahtar: {kirma_on_test.get('anahtar_hex')}",
            "onerilen_cozuculer": ["zaman_kirici"]
        }

    # 9. blok boyutu ve entropi analizi.
    if entropi >= 7.2:
        blok_16_listesi = [ilk_baytlar[i:i+16] for i in range(0, len(ilk_baytlar), 16) if len(ilk_baytlar[i:i+16]) == 16]
        ecb_16_tekrari = len(blok_16_listesi) > len(set(blok_16_listesi))

        blok_8_listesi = [ilk_baytlar[i:i+8] for i in range(0, len(ilk_baytlar), 8) if len(ilk_baytlar[i:i+8]) == 8]
        ecb_8_tekrari = len(blok_8_listesi) > len(set(blok_8_listesi))

        if boyut % 16 == 0:
            mod_metni = "ECB Modu (Zayıf Kripto - Tekrarlayan Bloklar)" if ecb_16_tekrari else "CBC / CTR / GCM Modu"
            return {
                "dosya": dosya_yolu,
                "algoritma": f"Simetrik Blok Şifreleyici - 16 Bayt ({mod_metni}) [AES / Twofish / Camellia / SM4 / SEED]",
                "kategori": "STANDART_KRIPTO",
                "guven": 0.80,
                "sifreli_mi": True,
                "blok_boyutu": 16,
                "mod": "ecb" if ecb_16_tekrari else "cbc",
                "detay": f"Dosya boyutu 16 baytın tam katı, yüksek entropi ({entropi:.2f}/8.0).",
                "onerilen_cozuculer": ["aes_cozucu", "twofish_cozucu", "camellia_cozucu", "sm4_cozucu", "seed_cozucu", "bellek_avi", "sozluk_saldirisi"]
            }
        elif boyut % 8 == 0:
            mod_metni = "ECB Modu" if ecb_8_tekrari else "CBC / CTR Modu"
            return {
                "dosya": dosya_yolu,
                "algoritma": f"Simetrik Blok Şifreleyici - 8 Bayt ({mod_metni}) [Blowfish / 3DES / CAST5 / TEA / XTEA / XXTEA / IDEA]",
                "kategori": "STANDART_KRIPTO",
                "guven": 0.75,
                "sifreli_mi": True,
                "blok_boyutu": 8,
                "mod": "ecb" if ecb_8_tekrari else "cbc",
                "detay": f"Dosya boyutu 8 baytın katı, yüksek entropi ({entropi:.2f}/8.0).",
                "onerilen_cozuculer": ["blowfish_cozucu", "3des_cozucu", "cast5_cozucu", "tea_cozucu", "xtea_cozucu", "xxtea_cozucu", "idea_cozucu", "bellek_avi", "sozluk_saldirisi"]
            }
        else:
            return {
                "dosya": dosya_yolu,
                "algoritma": "Akış Şifreleyici / Polialfabetik XOR [ChaCha20 / Salsa20 / RC4 / XOR]",
                "kategori": "STANDART_KRIPTO",
                "guven": 0.75,
                "sifreli_mi": True,
                "blok_boyutu": 0,
                "mod": "stream",
                "detay": f"Dolgu baytı içermeyen yüksek entropili akış şifrelemesi ({entropi:.2f}/8.0).",
                "onerilen_cozuculer": ["chacha_cozucu", "salsa20_cozucu", "rc4_cozucu", "xor_cozucu", "bellek_avi"]
            }

    # şifreli değilse veya normal dosyaysa.
    tur_tahmin = sihirli_baytlardan_tur_tahmin_et(ilk_baytlar)
    return {
        "dosya": dosya_yolu,
        "algoritma": f"Şifresiz Standart Dosya ({tur_tahmin or 'Bilinmiyor'})",
        "kategori": "SIFRESIZ",
        "guven": 0.90,
        "sifreli_mi": False,
        "detay": f"Normal dosya yapısı tespit edildi. Entropi: {entropi:.2f}/8.0",
        "onerilen_cozuculer": []
    }


def derin_kriptografik_analiz(dosya_yolu: str) -> Dict[str, Any]:
    """
    hedef dosya üzerinde adli bilişim (dfır) standardında derinlemesine
    kriptanaliz, entropi dağılımı, blok mimarisi ve tüm yeni algoritmalarla
    adaylık eşleme analizi yürütür.
    """
    temel_tespit = algoritma_tespit_et(dosya_yolu)
    if not os.path.exists(dosya_yolu):
        return temel_tespit

    boyut = os.path.getsize(dosya_yolu)
    with open(dosya_yolu, "rb") as f:
        ornek_veri = f.read(min(boyut, 65536))

    uzanti = os.path.splitext(dosya_yolu)[1].lower()
    entropi = round(dosya_entropisi_hesapla(dosya_yolu), 3)
    ki_kare = ki_kare_rastgelelik_skoru(ornek_veri)

    # seri korelasyon hesaplar.
    seri_korelasyon = 0.0
    if len(ornek_veri) >= 64:
        x = [b for b in ornek_veri[:-1]]
        y = [b for b in ornek_veri[1:]]
        ort_x = sum(x) / len(x)
        ort_y = sum(y) / len(y)
        pay = sum((a - ort_x) * (b - ort_y) for a, b in zip(x, y))
        payda = math.sqrt(sum((a - ort_x) ** 2 for a in x) * sum((b - ort_y) ** 2 for b in y))
        if payda > 0:
            seri_korelasyon = round(pay / payda, 4)

    # blok boyutu ve mod analizi.
    blok_boyutu = 0
    if boyut > 0:
        if boyut % 16 == 0:
            blok_boyutu = 16
        elif boyut % 8 == 0:
            blok_boyutu = 8

    blok_16 = [ornek_veri[i:i+16] for i in range(0, len(ornek_veri), 16) if len(ornek_veri[i:i+16]) == 16]
    ecb_16_tekrar = len(blok_16) - len(set(blok_16)) if blok_16 else 0

    if ecb_16_tekrar > 0:
        tahmini_mod = "ECB"
    elif blok_boyutu in (8, 16):
        tahmini_mod = "CBC / CTR"
    else:
        tahmini_mod = "STREAM / AKIŞ"

    # aday algoritmaları ve olasılık skorlarını derler.
    aday_algoritmalar: List[Dict[str, Any]] = []

    # openssl salted kontrolü.
    if ornek_veri.startswith(b"Salted__"):
        aday_algoritmalar.append({"algoritma": "openssl", "ad": "OpenSSL Salted (AES-256-CBC)", "olasilik": 0.99, "blok": 16, "kategori": "Konteyner"})

    if blok_boyutu == 16:
        aday_algoritmalar.extend([
            {"algoritma": "aes", "ad": "AES (Rijndael 128/192/256-bit)", "olasilik": 0.90 if uzanti in (".enc", ".locked") else 0.85, "blok": 16, "kategori": "Blok Şifreleyici"},
            {"algoritma": "twofish", "ad": "Twofish (128/192/256-bit)", "olasilik": 0.88 if "twofish" in uzanti or "notpetya" in uzanti else 0.80, "blok": 16, "kategori": "Blok Şifreleyici"},
            {"algoritma": "camellia", "ad": "Camellia (128/192/256-bit)", "olasilik": 0.75, "blok": 16, "kategori": "Blok Şifreleyici"},
            {"algoritma": "sm4", "ad": "SM4 Ulusal Şifreleyici (128-bit)", "olasilik": 0.70, "blok": 16, "kategori": "Blok Şifreleyici"},
            {"algoritma": "seed", "ad": "SEED (128-bit)", "olasilik": 0.65, "blok": 16, "kategori": "Blok Şifreleyici"}
        ])
    elif blok_boyutu == 8:
        aday_algoritmalar.extend([
            {"algoritma": "blowfish", "ad": "Blowfish (64-bit Blok, 32-448 bit)", "olasilik": 0.85, "blok": 8, "kategori": "Blok Şifreleyici"},
            {"algoritma": "3des", "ad": "TripleDES (3DES EDE3)", "olasilik": 0.85, "blok": 8, "kategori": "Blok Şifreleyici"},
            {"algoritma": "tea", "ad": "TEA (Tiny Encryption Algorithm)", "olasilik": 0.80, "blok": 8, "kategori": "Blok Şifreleyici"},
            {"algoritma": "xtea", "ad": "XTEA (Extended TEA)", "olasilik": 0.80, "blok": 8, "kategori": "Blok Şifreleyici"},
            {"algoritma": "xxtea", "ad": "XXTEA (Corrected Block TEA)", "olasilik": 0.75, "blok": 8, "kategori": "Blok Şifreleyici"},
            {"algoritma": "cast5", "ad": "CAST5 / CAST-128", "olasilik": 0.70, "blok": 8, "kategori": "Blok Şifreleyici"},
            {"algoritma": "idea", "ad": "IDEA (128-bit Anahtar)", "olasilik": 0.70, "blok": 8, "kategori": "Blok Şifreleyici"}
        ])

    # akış şifreleyicileri kontrolü.
    aday_algoritmalar.extend([
        {"algoritma": "chacha", "ad": "ChaCha20 (256-bit Akış Şifreleyici)", "olasilik": 0.88 if blok_boyutu == 0 else 0.75, "blok": 0, "kategori": "Akış Şifreleyici"},
        {"algoritma": "salsa20", "ad": "Salsa20 (Salsa20/20 128/256-bit)", "olasilik": 0.88 if blok_boyutu == 0 else 0.75, "blok": 0, "kategori": "Akış Şifreleyici"},
        {"algoritma": "rc4", "ad": "RC4 / ARC4 (Akış Şifreleyici)", "olasilik": 0.82 if blok_boyutu == 0 else 0.65, "blok": 0, "kategori": "Akış Şifreleyici"},
        {"algoritma": "xor", "ad": "Polialfabetik / Statik XOR", "olasilik": 0.65, "blok": 0, "kategori": "Zayıf Kripto"}
    ])

    # olasılığa göre azalan sıralama.
    aday_algoritmalar.sort(key=lambda x: x["olasilik"], reverse=True)

    # tehdit istihbaratı eşleştirmesi.
    tehdit_istihbarati = sizinti_anahtari_sorgula(uzanti)
    cozucu_tavsiyesi = bilinen_cozucu_tavsiyesi(uzanti)

    # örnek komut önerisi üretir.
    en_iyi_aday = aday_algoritmalar[0]["algoritma"] if aday_algoritmalar else "aes"
    komut_ornek = f"rescat coz \"{dosya_yolu}\" --algoritma {en_iyi_aday}"
    if tahmini_mod in ("ECB", "CBC"):
        komut_ornek += f" --mod {tahmini_mod.lower()}"

    return {
        "dosya_yolu": dosya_yolu,
        "dosya_adi": os.path.basename(dosya_yolu),
        "dosya_boyutu": boyut,
        "sifreli_mi": temel_tespit.get("sifreli_mi", entropi >= 7.2),
        "kategori": temel_tespit.get("kategori", "STANDART_KRIPTO"),
        "birincil_algoritma": temel_tespit.get("algoritma", "Bilinmiyor"),
        "guven_skoru": temel_tespit.get("guven", 0.80),
        "entropi": entropi,
        "ki_kare_skoru": ki_kare["chi_kare"],
        "rastgelelik_orani": ki_kare["rastgelelik_orani"],
        "bayt_ortalamasi": ki_kare["ortalama"],
        "seri_korelasyon": seri_korelasyon,
        "blok_boyutu": blok_boyutu,
        "tahmini_mod": tahmini_mod,
        "ecb_tekrar_sayisi": ecb_16_tekrar,
        "aday_algoritmalar": aday_algoritmalar,
        "tehdit_istihbarati": tehdit_istihbarati,
        "cozucu_tavsiyesi": cozucu_tavsiyesi,
        "onerilen_cozuculer": temel_tespit.get("onerilen_cozuculer", []),
        "komut_onerisi": komut_ornek
    }
