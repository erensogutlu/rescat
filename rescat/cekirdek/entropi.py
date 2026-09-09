import math
from collections import Counter
from typing import Dict, List, Tuple


def shannon_entropisi_hesapla(veri_baytlari: bytes) -> float:
    # bayt dizisinin shannon entropisini hesaplar.
    if not veri_baytlari:
        return 0.0

    toplam_bayt_sayisi = len(veri_baytlari)
    bayt_frekanslari = Counter(veri_baytlari)
    entropi_puani = 0.0

    for bayt_sayisi in bayt_frekanslari.values():
        olasilik = bayt_sayisi / toplam_bayt_sayisi
        entropi_puani -= olasilik * math.log2(olasilik)

    return round(entropi_puani, 4)


def dosya_entropisi_hesapla(dosya_yolu: str, maksimum_okuma: int = 10 * 1024 * 1024) -> float:
    # dosyanın genel entropisini hesaplar.
    try:
        with open(dosya_yolu, "rb") as dosya_nesnesi:
            okunan_veri = dosya_nesnesi.read(maksimum_okuma)
            return shannon_entropisi_hesapla(okunan_veri)
    except Exception:
        return 0.0


def kayan_pencere_entropisi(
    veri_baytlari: bytes,
    pencere_boyutu: int = 4096,
    adim_boyutu: int = 2048
) -> List[Tuple[int, float]]:
    # kayan pencereyle bölgesel entropi haritası çıkarır.
    toplam_boyut = len(veri_baytlari)
    if toplam_boyut == 0:
        return []

    harita: List[Tuple[int, float]] = []
    baslangic_ofseti = 0

    while baslangic_ofseti < toplam_boyut:
        bitis_ofseti = min(baslangic_ofseti + pencere_boyutu, toplam_boyut)
        dilim = veri_baytlari[baslangic_ofseti:bitis_ofseti]
        dilim_entropisi = shannon_entropisi_hesapla(dilim)
        harita.append((baslangic_ofseti, dilim_entropisi))

        if bitis_ofseti == toplam_boyut:
            break
        baslangic_ofseti += adim_boyutu

    return harita


def kismi_sifreleme_analizi(
    dosya_yolu: str,
    pencere_boyutu: int = 4096,
    esik_entropi: float = 7.2
) -> Dict[str, any]:
    # aralıklı şifrelenmiş bölgeleri tespit eder.
    with open(dosya_yolu, "rb") as dosya_nesnesi:
        tum_veri = dosya_nesnesi.read()

    toplam_boyut = len(tum_veri)
    if toplam_boyut == 0:
        return {
            "dosya_boyutu": 0,
            "genel_entropi": 0.0,
            "sifreli_mi": False,
            "kismi_sifreli_mi": False,
            "sifreli_bolge_orani": 0.0,
            "sifreli_araliklar": []
        }

    genel_entropi = shannon_entropisi_hesapla(tum_veri)
    entropi_haritasi = kayan_pencere_entropisi(tum_veri, pencere_boyutu=pencere_boyutu, adim_boyutu=pencere_boyutu)

    sifreli_dilim_sayisi = 0
    toplam_dilim_sayisi = len(entropi_haritasi)
    sifreli_araliklar: List[Tuple[int, int]] = []

    aralik_baslangici = None
    aralik_bitisi = None

    for ofset, entropi in entropi_haritasi:
        dilim_sonu = min(ofset + pencere_boyutu, toplam_boyut)
        if entropi >= esik_entropi:
            sifreli_dilim_sayisi += 1
            if aralik_baslangici is None:
                aralik_baslangici = ofset
            aralik_bitisi = dilim_sonu
        else:
            if aralik_baslangici is not None and aralik_bitisi is not None:
                sifreli_araliklar.append((aralik_baslangici, aralik_bitisi))
                aralik_baslangici = None
                aralik_bitisi = None

    # son bölge de şifreliyse aralığa ekler.
    if aralik_baslangici is not None and aralik_bitisi is not None:
        sifreli_araliklar.append((aralik_baslangici, aralik_bitisi))

    sifreli_oran = sifreli_dilim_sayisi / toplam_dilim_sayisi if toplam_dilim_sayisi > 0 else 0.0
    kismi_sifreli = 0.05 < sifreli_oran < 0.95
    tam_sifreli = sifreli_oran >= 0.95 or genel_entropi >= 7.4

    return {
        "dosya_boyutu": toplam_boyut,
        "genel_entropi": genel_entropi,
        "sifreli_mi": tam_sifreli or kismi_sifreli,
        "kismi_sifreli_mi": kismi_sifreli,
        "sifreli_bolge_orani": round(sifreli_oran * 100, 2),
        "sifreli_araliklar": sifreli_araliklar
    }
