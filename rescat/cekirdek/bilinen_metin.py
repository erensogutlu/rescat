from typing import Dict, List, Optional, Tuple


def xor_bayt_islemi(veri_bir: bytes, veri_iki: bytes) -> bytes:
    # iki bayt dizisi arasında xor işlemi.
    en_kisa_uzunluk = min(len(veri_bir), len(veri_iki))
    return bytes(veri_bir[indeks] ^ veri_iki[indeks] for indeks in range(en_kisa_uzunluk))


def xor_periyodu_tahmin_et(anahtar_akisi: bytes, maksimum_periyot: int = 128) -> Optional[int]:
    # anahtar akışındaki periyodik tekrar uzunluğunu bulur.
    if len(anahtar_akisi) < 8:
        return None

    sinir = min(maksimum_periyot, len(anahtar_akisi) // 2)

    for aday_periyot in range(1, sinir + 1):
        eslesme = True
        for indeks in range(aday_periyot, len(anahtar_akisi)):
            if anahtar_akisi[indeks] != anahtar_akisi[indeks % aday_periyot]:
                eslesme = False
                break
        if eslesme:
            return aday_periyot

    return None


def bilinen_metin_saldirisi_yap(
    orijinal_baytlar: bytes,
    sifreli_baytlar: bytes
) -> Dict[str, any]:
    # bilinen düz metin ile xor anahtarını veya akışını çıkarır.
    karsilastirma_uzunlugu = min(len(orijinal_baytlar), len(sifreli_baytlar))
    if karsilastirma_uzunlugu == 0:
        return {"hata": "karsilastirilacak veri yok"}

    # xor akışını çıkarır: şifreli ^ düz = anahtar.
    cikarilan_akis = xor_bayt_islemi(orijinal_baytlar, sifreli_baytlar)
    tahmin_edilen_periyot = xor_periyodu_tahmin_et(cikarilan_akis)

    kurtarilan_anahtar = None
    statik_xor_mu = False

    if tahmin_edilen_periyot is not None:
        kurtarilan_anahtar = cikarilan_akis[:tahmin_edilen_periyot]
        statik_xor_mu = True

    # blok yapısı analizi: olası blok şifreleme kontrolü.
    blok_eslesme_16 = False
    if karsilastirma_uzunlugu >= 32:
        # ilk 16 bayt ile sonraki blok farklarına bakar.
        blok_bir = sifreli_baytlar[0:16]
        blok_iki = sifreli_baytlar[16:32]
        if blok_bir == blok_iki:
            blok_eslesme_16 = True

    return {
        "karsilastirilan_bayt_sayisi": karsilastirma_uzunlugu,
        "statik_xor_mu": statik_xor_mu,
        "tahmin_edilen_periyot": tahmin_edilen_periyot,
        "kurtarilan_anahtar_hex": kurtarilan_anahtar.hex() if kurtarilan_anahtar else None,
        "kurtarilan_anahtar_ascii": kurtarilan_anahtar.decode("latin1", errors="replace") if kurtarilan_anahtar else None,
        "anahtar_akisi_ilk_32_hex": cikarilan_akis[:32].hex(),
        "ecb_tekrari_olabilir_mi": blok_eslesme_16
    }
