import os
import tempfile
import unittest
from rescat.cekirdek.entropi import (
    shannon_entropisi_hesapla,
    dosya_entropisi_hesapla,
    kismi_sifreleme_analizi
)


class TestEntropi(unittest.TestCase):
    # entropi hesaplama fonksiyonlarini test eden sinif
    def test_duz_metin_entropisi(self) -> None:
        # duz metin icin entropinin dusuk seviyede (3-5 arasi) olmasi beklenir
        ornek_metin = b"bu sadece siradan ve tekrarlayan bir metin ornegidir." * 50
        entropi_puani = shannon_entropisi_hesapla(ornek_metin)
        self.assertLess(entropi_puani, 5.0)

    def test_rastgele_sifreli_entropi(self) -> None:
        # kriptografik rastgele verinin entropisi 7.8 uzerinde olmalidir
        rastgele_veri = os.urandom(10000)
        entropi_puani = shannon_entropisi_hesapla(rastgele_veri)
        self.assertGreater(entropi_puani, 7.8)

    def test_kismi_sifreleme_tespiti(self) -> None:
        # baslangici sifreli sonu duz metin olan kismi sifreli dosya testi
        sifreli_parca = os.urandom(8192)
        duz_parca = b"A" * 8192
        birlestirilmis_veri = sifreli_parca + duz_parca

        with tempfile.NamedTemporaryFile(delete=False) as gecici_dosya:
            gecici_dosya.write(birlestirilmis_veri)
            gecici_yol = gecici_dosya.name

        try:
            analiz_sonucu = kismi_sifreleme_analizi(gecici_yol, pencere_boyutu=4096)
            self.assertTrue(analiz_sonucu["sifreli_mi"])
            self.assertTrue(analiz_sonucu["kismi_sifreli_mi"])
            self.assertGreater(len(analiz_sonucu["sifreli_araliklar"]), 0)
        finally:
            if os.path.exists(gecici_yol):
                os.remove(gecici_yol)


if __name__ == "__main__":
    unittest.main()
