import os
import tempfile
import unittest
from rescat.cozuculer.evrensel_cozucu import CozucuFabrikasi
from rescat.cozuculer.paralel_cozucu import ParalelCozucu
from rescat.cozuculer.aes_cozucu import AesCozucu
from rescat.cozuculer.blok_cozucu import BlokCozucu
from rescat.cozuculer.salsa20_cozucu import Salsa20Cozucu
from rescat.cozuculer.chacha_cozucu import ChaChaCozucu
from rescat.cozuculer.xor_cozucu import XorCozucu
from rescat.cozuculer.twofish_cozucu import TwofishCozucu


class TestEvrenselCozucuVeParalel(unittest.TestCase):
    def setUp(self):
        self.gecici_dizin = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.gecici_dizin.cleanup()

    def test_cozucu_fabrikasi_parametre_esnekligi(self):
        # algoritma ve algoritma_adi parametrelerinin her ikisi de calismali
        c1 = CozucuFabrikasi.cozucu_uret("aes", b"1234567890123456")
        self.assertIsInstance(c1, AesCozucu)

        c2 = CozucuFabrikasi.cozucu_uret(algoritma_adi="aes", anahtar_baytlari=b"1234567890123456")
        self.assertIsInstance(c2, AesCozucu)

        c3 = CozucuFabrikasi.cozucu_uret(algoritma="blowfish", anahtar_baytlari=b"12345678")
        self.assertIsInstance(c3, BlokCozucu)

        c4 = CozucuFabrikasi.cozucu_uret(algoritma_adi="blowfish", anahtar_baytlari=b"12345678")
        self.assertIsInstance(c4, BlokCozucu)

        c5 = CozucuFabrikasi.cozucu_uret(algoritma="salsa20", anahtar_baytlari=b"1234567890123456")
        self.assertIsInstance(c5, Salsa20Cozucu)

        c6 = CozucuFabrikasi.cozucu_uret(algoritma="twofish", anahtar_baytlari=b"1234567890123456")
        self.assertIsInstance(c6, TwofishCozucu)

    def test_hedef_cikti_dizini_kaynak_dosyayi_degistirmez(self):
        # yedek_al=False ve hedef_cikti_dizini verildiginde orijinal kaynak dosya yerinde korunmalidir
        cikti_dizini = os.path.join(self.gecici_dizin.name, "cikti")
        kaynak_dosya = os.path.join(self.gecici_dizin.name, "kaynak.txt")

        orijinal_icerik = b"Sifreli veri icerigi 12345678"
        with open(kaynak_dosya, "wb") as f:
            f.write(orijinal_icerik)

        cozucu = XorCozucu(
            anahtar_baytlari=b"\x01",
            yedek_al=False,
            hedef_cikti_dizini=cikti_dizini
        )
        sonuc = cozucu.tekil_dosya_coz(kaynak_dosya)
        self.assertTrue(sonuc.get("basarili"))

        # Kaynak dosya orijinal haliyle kalmali
        with open(kaynak_dosya, "rb") as f:
            self.assertEqual(f.read(), orijinal_icerik)

        # Cikti dosyasina cozulmus veri yazilmis olmali
        hedef_dosya = os.path.join(cikti_dizini, "kaynak.txt")
        self.assertTrue(os.path.exists(hedef_dosya))
        with open(hedef_dosya, "rb") as f:
            self.assertEqual(f.read(), bytes(b ^ 1 for b in orijinal_icerik))

    def test_paralel_cozucu_genisletilmis_algoritma(self):
        # Paralel cozucunun blowfish veya salsa20 gibi genisletilmis algoritmalarla calismasi
        test_dizin = os.path.join(self.gecici_dizin.name, "paralel_test")
        os.makedirs(test_dizin, exist_ok=True)

        dosya1 = os.path.join(test_dizin, "f1.enc")
        with open(dosya1, "wb") as f:
            f.write(b"ABCDEFGH12345678")

        paralel = ParalelCozucu(
            anahtar_baytlari=b"12345678",
            algoritma="blowfish",
            mod_adi="ecb",
            is_parcacigi_sayisi=1,
            kuru_calistirma=True
        )
        sonuclar = paralel.dizini_paralel_coz(test_dizin)
        self.assertEqual(len(sonuclar), 1)
        self.assertTrue(sonuclar[0].get("basarili"))


if __name__ == "__main__":
    unittest.main()
