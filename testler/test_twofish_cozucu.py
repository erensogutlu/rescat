import os
import tempfile
import unittest
from rescat.cozuculer.twofish_cozucu import TwofishEngine, TwofishCozucu


class TestTwofishCozucu(unittest.TestCase):
    def setUp(self):
        self.gecici_dizin = tempfile.TemporaryDirectory()
        self.anahtar_128 = b"1234567890123456"
        self.anahtar_256 = b"0123456789abcdef0123456789abcdef"

    def tearDown(self):
        self.gecici_dizin.cleanup()

    def test_twofish_blok_roundtrip_128(self):
        engine = TwofishEngine(self.anahtar_128)
        duz_blok = b"HelloTwofish128B"
        sifreli = engine.blok_sifrele(duz_blok)
        self.assertNotEqual(sifreli, duz_blok)

        cozulmus = engine.blok_coz(sifreli)
        self.assertEqual(cozulmus, duz_blok)

    def test_twofish_blok_roundtrip_256(self):
        engine = TwofishEngine(self.anahtar_256)
        duz_blok = b"Twofish256BitBlk"
        sifreli = engine.blok_sifrele(duz_blok)
        self.assertNotEqual(sifreli, duz_blok)

        cozulmus = engine.blok_coz(sifreli)
        self.assertEqual(cozulmus, duz_blok)

    def test_twofish_dosya_cozumu_ecb(self):
        engine = TwofishEngine(self.anahtar_256)
        # 16 baytlık PDF başlığı
        pdf_blok = b"%PDF-1.4\n1234567"
        sifreli = engine.blok_sifrele(pdf_blok)

        hedef_dosya = os.path.join(self.gecici_dizin.name, "rapor.pdf.twofish")
        with open(hedef_dosya, "wb") as f:
            f.write(sifreli)

        cozucu = TwofishCozucu(
            anahtar_baytlari=self.anahtar_256,
            mod_adi="ecb",
            iv_dosya_basinda_mi=False,
            yedek_al=True
        )
        sonuc = cozucu.tekil_dosya_coz(hedef_dosya)

        self.assertTrue(sonuc.get("basarili"))
        self.assertEqual(sonuc.get("dogrulanan_tur"), "pdf")

        with open(hedef_dosya, "rb") as f:
            self.assertEqual(f.read(), pdf_blok)


if __name__ == "__main__":
    unittest.main()
