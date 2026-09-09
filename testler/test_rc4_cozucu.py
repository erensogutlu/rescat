import os
import tempfile
import unittest
from rescat.cozuculer.rc4_cozucu import Rc4Cozucu, saf_python_rc4


class TestRc4Cozucu(unittest.TestCase):
    def setUp(self):
        self.gecici_dizin = tempfile.TemporaryDirectory()
        self.anahtar = b"VerySecretKey123"

    def tearDown(self):
        self.gecici_dizin.cleanup()

    def test_rc4_bayt_cozumu(self):
        duz_metin = b"Antigravity Ransomware Decryption Toolkit Pure Python and Cryptography RC4"
        # RC4 simetrik bir akış şifreleyicidir; aynı anahtar ile şifreleme ve çözme simetriktir
        sifreli = saf_python_rc4(self.anahtar, duz_metin)
        self.assertNotEqual(sifreli, duz_metin)

        cozucu = Rc4Cozucu(anahtar_baytlari=self.anahtar)
        cozulmus = cozucu.baytlari_coz(sifreli)
        self.assertEqual(cozulmus, duz_metin)

    def test_rc4_dosya_cozumu(self):
        pdf_verisi = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF"
        sifreli_pdf = saf_python_rc4(self.anahtar, pdf_verisi)

        hedef_dosya = os.path.join(self.gecici_dizin.name, "belge.pdf.locked")
        with open(hedef_dosya, "wb") as f:
            f.write(sifreli_pdf)

        cozucu = Rc4Cozucu(anahtar_baytlari=self.anahtar, yedek_al=True)
        sonuc = cozucu.tekil_dosya_coz(hedef_dosya)

        self.assertTrue(sonuc.get("basarili"))
        self.assertEqual(sonuc.get("dogrulanan_tur"), "pdf")

        # Dosya içeriğinin düzeltildiğini doğrula
        with open(hedef_dosya, "rb") as f:
            self.assertEqual(f.read(), pdf_verisi)

        # .bak yedeğinin alındığını doğrula
        self.assertTrue(os.path.exists(hedef_dosya + ".bak"))


if __name__ == "__main__":
    unittest.main()
