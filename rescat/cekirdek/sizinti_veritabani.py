from typing import Dict, Optional, List, Any
from rescat.cekirdek.djvu_veritabani import (
    DJVU_BILINEN_OFFLINE_ANAHTARLAR,
    uzantiya_gore_offline_anahtar_al,
    STOP_DJVU_YENI_OFFLINE_ANAHTAR_HEX,
    STOP_DJVU_ESKI_OFFLINE_ANAHTAR_HEX,
)

DJVU_GENISLETILMIS_OFFLINE_ANAHTARLAR = DJVU_BILINEN_OFFLINE_ANAHTARLAR

# -----------------------------------------------------------------------------
# kamuya açıklanmış çözücü ve anahtar istihbaratı.
# -----------------------------------------------------------------------------
# bilinen zafiyetler ve çözücü stratejileri veritabanı.
# cert-eu ve no more ransom onaylı kurtarma stratejileri.

SIZINTI_MASTER_VERITABANI: Dict[str, Dict[str, Any]] = {
    "babuk": {
        "zararli": "Babuk Ransomware",
        "algoritma": "ChaCha20-Poly1305 / Curve25519",
        "kaynak": "Babuk Source Code Leak 2021",
        "aciklama": "Sızdırılan builder kaynak kodunda gömülü ECDH ve ChaCha20 çözücü parametreleri.",
        "cozucu_turu": "chacha_poly1305",
        "durum": "Özel anahtar veya RAM matris dökümü ile kurtarılabilir"
    },
    "crysis": {
        "zararli": "CrySiS / Dharma",
        "algoritma": "AES-256 + RSA-1024",
        "kaynak": "BleepingComputer Master Keys Release",
        "aciklama": "Operatör tarafından kamuya açıklanan master RSA özel anahtar koleksiyonu.",
        "cozucu_turu": "aes",
        "durum": "NoMoreRansom CrySiS Decryptor veya PEM RSA anahtarı ile tam kurtarma"
    },
    "gandcrab": {
        "zararli": "GandCrab (v1 - v5.2)",
        "algoritma": "AES-256 / Salsa20 + RSA-2048",
        "kaynak": "Bitdefender / Europol / FBI Ortak Operasyonu",
        "aciklama": "v1 - v5.2 arasındaki tüm sürümler için operasyonel master anahtar seti.",
        "cozucu_turu": "salsa20",
        "durum": "Bitdefender GandCrab Decryptor ile kurtarılabilir"
    },
    "conti": {
        "zararli": "Conti Ransomware",
        "algoritma": "ChaCha20 + RSA-4096",
        "kaynak": "ContiLeaks 2022",
        "aciklama": "Conti kaynak kodları, locker mekanizması ve kurban anahtarları sızdırıldı.",
        "cozucu_turu": "chacha",
        "durum": "Bellek anahtarı veya sızan kurban anahtarlarıyla AES/ChaCha çözülebilir"
    },
    "lockbit3": {
        "zararli": "LockBit 3.0 (LockBit Black)",
        "algoritma": "AES-256-GCM / ChaCha20-Poly1305",
        "kaynak": "LockBit 3.0 Builder Leak (Eylül 2022)",
        "aciklama": "Builder sızıntısı ve kısmi (intermittent) şifreleme profili.",
        "cozucu_turu": "chacha_poly1305",
        "durum": "Kısmi şifre motoru ve RAM anahtar avcısı ile kurtarılabilir"
    },
    "revil": {
        "zararli": "REvil / Sodinokibi",
        "algoritma": "Salsa20/20 + Curve25519",
        "kaynak": "Bitdefender / Europol Operasyonu",
        "aciklama": "Salsa20 akış şifresi ve bellek durum matrisinden anahtar çıkarma.",
        "cozucu_turu": "salsa20",
        "durum": "Bellek durum matrisi ('expand 32-byte k') ile kurtarma mümkün"
    },
    "petya": {
        "zararli": "Petya / Mischa / GoldenEye",
        "algoritma": "Salsa20/20 (16/32 Bayt Anahtar)",
        "kaynak": "Zayıf PRNG ve Kriptoanaliz (SecuriteInfo / Hasherezade)",
        "aciklama": "Salsa20 anahtar çizelgesi zayıf tohumlamadan tersine mühendislikle çözülebilir.",
        "cozucu_turu": "salsa20",
        "durum": "PRNG tohum kaba kuvveti ile çözülebilir"
    },
    "notpetya": {
        "zararli": "NotPetya / ExPetr",
        "algoritma": "Twofish-CBC / Salsa20",
        "kaynak": "Wiper Analizi (Kaspersky / Microsoft)",
        "aciklama": "Aslında bir wiper olsa da dosya başı Twofish/XOR ile şifrelenenler kurtarılabilir.",
        "cozucu_turu": "twofish",
        "durum": "Twofish-CBC motoru ile çözülebilir"
    },
    "djvu": {
        "zararli": "Stop/Djvu",
        "algoritma": "AES-256-CBC (Offline Master Keys)",
        "kaynak": "Emsisoft STOPDecrypter / Michael Gillespie",
        "aciklama": "C2 bağlantısı kurulamayan ('t1' / 't2') tüm varyantlar için yerel offline anahtarlar.",
        "cozucu_turu": "djvu",
        "durum": "Offline anahtar veritabanı ile %100 yerel kurtarma mümkün"
    }
}


def sizinti_anahtari_sorgula(uzanti_veya_ad: str) -> Optional[Dict[str, Any]]:
    """
    belirtilen uzantı veya ransomware adı için sızdırılmış anahtar veya
    çözüm stratejisini döndürür.
    """
    temiz = uzanti_veya_ad.lower().lstrip(".")

    # stop/djvu çevrim dışı anahtar kontrolü.
    if temiz in DJVU_BILINEN_OFFLINE_ANAHTARLAR:
        anahtar_hex = uzantiya_gore_offline_anahtar_al(temiz)
        return {
            "zararli": f"Stop/Djvu (.{temiz})",
            "algoritma": "AES-256-CBC (Offline Master Key)",
            "anahtar_hex": anahtar_hex,
            "durum": "Offline anahtarla %100 yerel kurtarma mümkün",
            "cozucu_turu": "djvu"
        }

    for anahtar_adi, veri in SIZINTI_MASTER_VERITABANI.items():
        if anahtar_adi in temiz:
            return veri

    return None


BILINEN_COZUCU_VERITABANI: Dict[str, Dict[str, str]] = {
    "babuk": {
        "zararli_ailesi": "Babuk Ransomware",
        "durum": "ChaCha20-Poly1305 ve RAM anahtarlarıyla çözüm mevcut",
        "arac_baglantisi": "rescat coz --algoritma chacha_poly1305"
    },
    "conti": {
        "zararli_ailesi": "Conti",
        "durum": "Bellek anahtar avcısı ve ChaCha20 çözücü entegre",
        "arac_baglantisi": "rescat coz --algoritma chacha"
    },
    "lockbit": {
        "zararli_ailesi": "LockBit 3.0 (Black)",
        "durum": "Kısmi şifreleme ve ChaCha20-Poly1305/AES-GCM çözümleri",
        "arac_baglantisi": "rescat coz --algoritma chacha_poly1305 --kismi"
    },
    "revil": {
        "zararli_ailesi": "REvil / Sodinokibi",
        "durum": "Salsa20 akış şifresi bellek anahtarıyla kurtarılabilir",
        "arac_baglantisi": "rescat coz --algoritma salsa20"
    },
    "sodinokibi": {
        "zararli_ailesi": "REvil / Sodinokibi",
        "durum": "Salsa20 akış şifresi bellek anahtarıyla kurtarılabilir",
        "arac_baglantisi": "rescat coz --algoritma salsa20"
    },
    "petya": {
        "zararli_ailesi": "Petya / Mischa",
        "durum": "Salsa20/20 algoritması yerel çözücüyle desteklenir",
        "arac_baglantisi": "rescat coz --algoritma salsa20"
    },
    "notpetya": {
        "zararli_ailesi": "NotPetya",
        "durum": "Twofish-CBC ve Salsa20 motoru entegre",
        "arac_baglantisi": "rescat coz --algoritma twofish"
    },
    "djvu": {
        "zararli_ailesi": "Stop/Djvu",
        "durum": "rescat offline anahtar veritabanı ile anında çözüm",
        "arac_baglantisi": "rescat otonom"
    }
}


def bilinen_cozucu_tavsiyesi(uzanti_veya_ad: str) -> Optional[Dict[str, str]]:
    temiz = uzanti_veya_ad.lower().lstrip(".")
    for anahtar, tavsiye in BILINEN_COZUCU_VERITABANI.items():
        if anahtar in temiz:
            return tavsiye
    return None
