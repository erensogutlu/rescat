import os
import unittest
from rescat.cozuculer.evrensel_cozucu import CozucuFabrikasi
from rescat.cozuculer.rc4_cozucu import Rc4Cozucu, saf_python_rc4
from rescat.cozuculer.salsa20_cozucu import Salsa20Cozucu
from rescat.cozuculer.twofish_cozucu import TwofishCozucu
from rescat.cozuculer.tea_cozucu import TeaCozucu, XteaCozucu, XxteaCozucu
from rescat.cozuculer.blok_cozucu import BlokCozucu
from rescat.cozuculer.aes_cozucu import AesCozucu
from rescat.cozuculer.chacha_cozucu import ChaChaCozucu
from rescat.cozuculer.openssl_cozucu import OpenSslCozucu


class TestEvrenselKatalog(unittest.TestCase):
    def setUp(self):
        self.anahtar_16 = b"0123456789abcdef"
        self.anahtar_32 = b"0123456789abcdef0123456789abcdef"

    def test_katalog_listesi(self):
        algolar = CozucuFabrikasi.desteklenen_algoritmalari_listele()
        beklenenler = [
            "aes", "chacha20", "salsa20", "rc4", "twofish", "blowfish",
            "3des", "camellia", "tea", "xtea", "xxtea", "cast5",
            "idea", "seed", "sm4", "openssl", "xor", "djvu"
        ]
        for b in beklenenler:
            self.assertIn(b, algolar)

    def test_fabrika_cozucu_uretimi(self):
        self.assertIsInstance(CozucuFabrikasi.cozucu_uret("rc4", self.anahtar_16), Rc4Cozucu)
        self.assertIsInstance(CozucuFabrikasi.cozucu_uret("salsa20", self.anahtar_32), Salsa20Cozucu)
        self.assertIsInstance(CozucuFabrikasi.cozucu_uret("twofish", self.anahtar_32), TwofishCozucu)
        self.assertIsInstance(CozucuFabrikasi.cozucu_uret("tea", self.anahtar_16), TeaCozucu)
        self.assertIsInstance(CozucuFabrikasi.cozucu_uret("xtea", self.anahtar_16), XteaCozucu)
        self.assertIsInstance(CozucuFabrikasi.cozucu_uret("xxtea", self.anahtar_16), XxteaCozucu)
        self.assertIsInstance(CozucuFabrikasi.cozucu_uret("blowfish", self.anahtar_16), BlokCozucu)
        self.assertIsInstance(CozucuFabrikasi.cozucu_uret("3des", b"123456781234567812345678"), BlokCozucu)
        self.assertIsInstance(CozucuFabrikasi.cozucu_uret("camellia", self.anahtar_16), BlokCozucu)
        self.assertIsInstance(CozucuFabrikasi.cozucu_uret("aes", self.anahtar_16), AesCozucu)
        self.assertIsInstance(CozucuFabrikasi.cozucu_uret("chacha20", self.anahtar_32), ChaChaCozucu)
        self.assertIsInstance(CozucuFabrikasi.cozucu_uret("openssl", self.anahtar_16), OpenSslCozucu)

    def test_aday_anahtar_otomatik_dene_rc4(self):
        # RC4 ile şifrelenmiş bir PDF dosyası
        pdf_verisi = b"%PDF-1.4\nTest PDF Body Contents\n%%EOF"
        sifreli = saf_python_rc4(self.anahtar_16, pdf_verisi)

        sonuc = CozucuFabrikasi.aday_anahtarla_otomatik_dene(sifreli, self.anahtar_16)
        self.assertIsNotNone(sonuc)
        self.assertTrue(sonuc["basarili"])
        self.assertEqual(sonuc["algoritma"], "rc4")
        self.assertEqual(sonuc["dogrulanan_tur"], "pdf")


if __name__ == "__main__":
    unittest.main()
