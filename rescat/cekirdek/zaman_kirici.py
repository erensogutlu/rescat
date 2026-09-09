import os
import time
from typing import Any, Dict, List, Optional, Tuple, Union
from rescat.cekirdek.dosya_tanimlayici import BILINEN_SIHIRLI_BAYTLAR, format_icerik_dogrula, sihirli_baytlardan_tur_tahmin_et


class LcgRastgele:
    # standart lcg algoritması.
    def __init__(self, tohum: int) -> None:
        # lcg başlangıç durumunu atar.
        self.durum: int = tohum & 0xFFFFFFFF

    def sonraki_sayi(self) -> int:
        # glibc lcg formülünü çalıştırır.
        self.durum = (self.durum * 1103515245 + 12345) & 0x7FFFFFFF
        return self.durum

    def rastgele_baytlar(self, adet: int) -> bytes:
        # belirtilen sayıda rastgele bayt dizisi üretir.
        uretilen = bytearray(adet)
        for indeks in range(adet):
            uretilen[indeks] = self.sonraki_sayi() & 0xFF
        return bytes(uretilen)


class DotNetRastgele:
    """
    microsoft .net framework system.random (knuth subtractive generator) simulasyonu.
    chaos, yashma ve bircok c# fidye yazilimi tarafindan kullanilir.
    """
    def __init__(self, tohum: int) -> None:
        self.tohum = tohum & 0x7FFFFFFF
        self.tohum_dizisi = [0] * 56
        self.inext = 0
        self.inextp = 21

        mj = (161803398 - self.tohum) & 0x7FFFFFFF
        self.tohum_dizisi[55] = mj
        mk = 1
        for i in range(1, 55):
            ii = (21 * i) % 55
            self.tohum_dizisi[ii] = mk
            mk = (mj - mk) & 0x7FFFFFFF
            mj = self.tohum_dizisi[ii]

        for k in range(1, 5):
            for i in range(1, 56):
                self.tohum_dizisi[i] = (self.tohum_dizisi[i] - self.tohum_dizisi[1 + (i + 30) % 55]) & 0x7FFFFFFF

    def sonraki(self) -> int:
        self.inext += 1
        if self.inext >= 56:
            self.inext = 1
        self.inextp += 1
        if self.inextp >= 56:
            self.inextp = 1

        sayi = (self.tohum_dizisi[self.inext] - self.tohum_dizisi[self.inextp]) & 0x7FFFFFFF
        self.tohum_dizisi[self.inext] = sayi
        return sayi

    def rastgele_baytlar(self, adet: int) -> bytes:
        cikis = bytearray(adet)
        for i in range(adet):
            cikis[i] = self.sonraki() % 256
        return bytes(cikis)


def dosya_zaman_damgasi_al(dosya_yolu: str) -> int:
    # dosya zaman damgasını saniye cinsinden döndürür.
    try:
        istatistik = os.stat(dosya_yolu)
        return int(istatistik.st_mtime)
    except Exception:
        return int(time.time())


def zaman_tabanli_xor_kir(
    sifreli_baytlar: Union[bytes, bytearray, str],
    merkez_zaman: int,
    aralik_saniye: int = 3600,
    anahtar_uzunlugu: int = 16,
    beklenen_uzanti: Optional[str] = None,
    arama_yaricapi_saniye: Optional[int] = None
) -> Optional[Dict[str, Any]]:
    # zaman tabanlı tohumu ve xor anahtarını tespit eder.
    if arama_yaricapi_saniye is not None:
        aralik_saniye = arama_yaricapi_saniye

    if isinstance(sifreli_baytlar, str):
        if os.path.isfile(sifreli_baytlar):
            with open(sifreli_baytlar, "rb") as dosya:
                ham_baytlar = dosya.read(1024)
        else:
            ham_baytlar = sifreli_baytlar.encode("utf-8")
    else:
        ham_baytlar = bytes(sifreli_baytlar)

    baslangic_zamani = merkez_zaman - aralik_saniye
    bitis_zamani = merkez_zaman + aralik_saniye

    hedef_imza = None
    if beklenen_uzanti and beklenen_uzanti.lower() in BILINEN_SIHIRLI_BAYTLAR:
        hedef_imza = BILINEN_SIHIRLI_BAYTLAR[beklenen_uzanti.lower()]

    kontrol_uzunlugu = min(len(ham_baytlar), 32)
    sifreli_ilk_blok = ham_baytlar[:kontrol_uzunlugu]

    for aday_tohum in range(baslangic_zamani, bitis_zamani + 1):
        for tip, uretec in (("C-LCG", LcgRastgele(aday_tohum)), (".NET-Random", DotNetRastgele(aday_tohum))):
            aday_anahtar = uretec.rastgele_baytlar(anahtar_uzunlugu)

            # ilk baytları xor ile çözer.
            deneme_cozum = bytearray(kontrol_uzunlugu)
            for indeks in range(kontrol_uzunlugu):
                deneme_cozum[indeks] = sifreli_ilk_blok[indeks] ^ aday_anahtar[indeks % anahtar_uzunlugu]

            # yapısal bütünlüğü doğrular.
            gecerli, tespit_turu = format_icerik_dogrula(bytes(deneme_cozum), beklenen_uzanti)
            if gecerli and tespit_turu:
                if beklenen_uzanti and tespit_turu != beklenen_uzanti.lower():
                    pass
                else:
                    return {
                        "basarili": True,
                        "prng_tipi": tip,
                        "kurtarilan_tohum": aday_tohum,
                        "zaman_farki_saniye": aday_tohum - merkez_zaman,
                        "anahtar_hex": aday_anahtar.hex(),
                        "kurtarilan_anahtar_hex": aday_anahtar.hex(),
                        "anahtar_baytlar": aday_anahtar,
                        "dogrulanan_tur": tespit_turu
                    }

    return None
