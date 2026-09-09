import os
import tempfile
import unittest
from rescat.cekirdek.baslik_onarici import baslik_yama
from rescat.cekirdek.dosya_tanimlayici import sihirli_baytlardan_tur_tahmin_et


class TestBaslikOnarici(unittest.TestCase):
    # kismi sifrelenmis baslik onarma testi
    def test_sqlite_baslik_onarma(self) -> None:
        # basligi ezilmis sahte bir sqlite dosyasi
        sahte_hasarli_icerik = b"LOCKED_BY_RANSOMWARE" * 10 + b"\x00" * 200 + b"VERITABANI_TABLO_VERILERI" * 20

        with tempfile.NamedTemporaryFile(delete=False) as gecici_hasarli:
            gecici_hasarli.write(sahte_hasarli_icerik)
            gecici_yol = gecici_hasarli.name

        onarilan_yol = gecici_yol + ".onarıldı"

        try:
            sonuc = baslik_yama(
                hasarli_dosya_yolu=gecici_yol,
                hedef_format="sqlite",
                cikti_dosya_yolu=onarilan_yol,
                ezilen_bayt_boyutu=100
            )

            self.assertTrue(sonuc["basarili"])

            with open(onarilan_yol, "rb") as f_onarilan:
                onarilan_baytlar = f_onarilan.read()

            self.assertEqual(sihirli_baytlardan_tur_tahmin_et(onarilan_baytlar), "sqlite")
        finally:
            if os.path.exists(gecici_yol):
                os.remove(gecici_yol)
            if os.path.exists(onarilan_yol):
                os.remove(onarilan_yol)

    def test_format_anahtari_ve_jpeg_destegi(self) -> None:
        sahte_hasarli_jpeg = b"BOZUK_HEADER" * 10 + b"JPEG_DATA" * 50
        with tempfile.NamedTemporaryFile(delete=False, suffix=".jpeg") as gecici_dosya:
            gecici_dosya.write(sahte_hasarli_jpeg)
            gecici_yol = gecici_dosya.name

        onarilan_yol = gecici_yol + ".onarildi"
        try:
            # format_anahtari kwarg destegini test et
            sonuc = baslik_yama(
                gecici_yol,
                format_anahtari="jpeg",
                cikti_dosya_yolu=onarilan_yol,
                ezilen_bayt_boyutu=120
            )
            self.assertTrue(sonuc["basarili"])
            with open(onarilan_yol, "rb") as f_onarilan:
                self.assertEqual(f_onarilan.read()[:2], b"\xff\xd8")
        finally:
            if os.path.exists(gecici_yol):
                os.remove(gecici_yol)
            if os.path.exists(onarilan_yol):
                os.remove(onarilan_yol)


if __name__ == "__main__":
    unittest.main()
