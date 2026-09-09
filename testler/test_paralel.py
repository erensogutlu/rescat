import os
import shutil
import tempfile
import unittest
from rescat.cozuculer.paralel_cozucu import ParalelCozucu
from rescat.cozuculer.akici_cozucu import AkiciCozucu


class TestParalelVeAkici(unittest.TestCase):
    # paralel cozucu ve akiskan streaming testleri
    def setUp(self) -> None:
        # gecici calisma dizini olustur
        self.gecici_dizin = tempfile.mkdtemp()

    def tearDown(self) -> None:
        # gecici dizini temizle
        if os.path.exists(self.gecici_dizin):
            shutil.rmtree(self.gecici_dizin)

    def test_paralel_cozucu(self) -> None:
        # birden fazla dosyayi coklu islem havuzunda cozdur
        anahtar = b"PARALEL_KEY_1234"
        dosya_sayisi = 10

        # 10 adet xor sifreli dosya olustur
        for indeks in range(dosya_sayisi):
            dosya_yolu = os.path.join(self.gecici_dizin, f"dosya_{indeks}.enc")
            duz_veri = f"Orijinal icerik satiri {indeks}".encode("utf-8")
            sifreli = bytes(b ^ anahtar[i % len(anahtar)] for i, b in enumerate(duz_veri))
            with open(dosya_yolu, "wb") as f:
                f.write(sifreli)

        # paralel cozucu ile coz
        paralel = ParalelCozucu(
            anahtar_baytlari=anahtar,
            algoritma="xor",
            is_parcacigi_sayisi=2,
            yedek_al=False
        )

        sonuclar = paralel.dizini_paralel_coz(self.gecici_dizin, uzanti_filtresi=".enc")
        self.assertEqual(len(sonuclar), dosya_sayisi)
        for sonuc in sonuclar:
            self.assertTrue(sonuc["basarili"])

    def test_akici_cozucu(self) -> None:
        # akiskan parca parca streaming cozme testi
        anahtar = b"1234567812345678"
        kaynak_yol = os.path.join(self.gecici_dizin, "buyuk_dosya.bin")
        hedef_yol = os.path.join(self.gecici_dizin, "buyuk_dosya_cozuldu.bin")

        orijinal_veri = b"A" * 50000 + b"B" * 50000
        # xor ile sifrele
        sifreli_veri = bytes(b ^ anahtar[i % len(anahtar)] for i, b in enumerate(orijinal_veri))
        with open(kaynak_yol, "wb") as f:
            f.write(sifreli_veri)

        akici = AkiciCozucu(
            anahtar_baytlari=anahtar,
            algoritma_adi="xor",
            tampon_boyutu=1024,
            yedek_al=False
        )

        sonuc = akici.akiskan_dosya_coz(kaynak_yol)
        self.assertTrue(sonuc["basarili"])

        with open(sonuc["hedef_dosya"], "rb") as f_cozulmus:
            kurtarilan = f_cozulmus.read()

        self.assertEqual(kurtarilan, orijinal_veri)


if __name__ == "__main__":
    unittest.main()
