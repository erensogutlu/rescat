import unittest
import os
import tempfile
import time
from rescat.cekirdek.otomatik_crib_drag import OtomatikCribDragMotoru
from rescat.cekirdek.zaman_kirici import zaman_tabanli_xor_kir, DotNetRastgele


class TestCribDragVePrng(unittest.TestCase):
    def setUp(self):
        self.gecici_dizin = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.gecici_dizin.cleanup()

    def test_otomatik_crib_dragging_anahtarsiz_cozum(self):
        # 1. Iki farkli dosya (biri PDF, biri PNG) ayni keystream ile sifrelenir (Nonce reuse zaafiyeti)
        pdf_veri = b"%PDF-1.7\n%Dokuman icerigi burada yer almaktadir" * 10
        png_veri = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + b"Resim govde pikselleri" * 10

        ortak_keystream = os.urandom(max(len(pdf_veri), len(png_veri)))

        c1 = bytes(pdf_veri[i] ^ ortak_keystream[i] for i in range(len(pdf_veri)))
        c2 = bytes(png_veri[i] ^ ortak_keystream[i] for i in range(len(png_veri)))

        dosya1 = os.path.join(self.gecici_dizin.name, "rapor.pdf.locked")
        dosya2 = os.path.join(self.gecici_dizin.name, "logo.png.locked")

        with open(dosya1, "wb") as f1, open(dosya2, "wb") as f2:
            f1.write(c1)
            f2.write(c2)

        # 2. Otomatik Crib-Drag ile anahtarsiz coz
        sonuc = OtomatikCribDragMotoru.dosyadan_anahtarsiz_coz(dosya1, dosya2)
        self.assertTrue(sonuc.get("basarili"))
        self.assertEqual(sonuc.get("dosya1_tur"), "pdf")
        self.assertEqual(sonuc.get("dosya2_tur"), "png")

    def test_dotnet_random_zaman_tabanli_kirici(self):
        # .NET System.Random tohumu ile sifrelenmis dosya
        simdi = int(time.time()) - 20
        uretec = DotNetRastgele(simdi)
        anahtar = uretec.rastgele_baytlar(16)

        orijinal = b"%PDF-1.4\n" + b"DotNet Ransomware Test Dokumani" * 5
        sifreli = bytearray(len(orijinal))
        for i in range(len(orijinal)):
            sifreli[i] = orijinal[i] ^ anahtar[i % 16]

        sonuc = zaman_tabanli_xor_kir(
            sifreli_baytlar=bytes(sifreli),
            merkez_zaman=simdi,
            aralik_saniye=60,
            anahtar_uzunlugu=16,
            beklenen_uzanti="pdf"
        )
        self.assertIsNotNone(sonuc)
        self.assertTrue(sonuc.get("basarili"))
        self.assertEqual(sonuc.get("prng_tipi"), ".NET-Random")
        self.assertEqual(sonuc.get("dogrulanan_tur"), "pdf")


if __name__ == "__main__":
    unittest.main()
