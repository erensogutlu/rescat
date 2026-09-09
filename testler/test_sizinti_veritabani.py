import unittest
from rescat.cekirdek.sizinti_veritabani import sizinti_anahtari_sorgula, DJVU_GENISLETILMIS_OFFLINE_ANAHTARLAR


class TestSizintiVeritabani(unittest.TestCase):
    """
    Sizinti ve serbest birakilmis master anahtar veritabani testleri.
    """

    def test_djvu_genisletilmis_offline_anahtarlar(self) -> None:
        sonuc_gero = sizinti_anahtari_sorgula("gero")
        self.assertIsNotNone(sonuc_gero)
        self.assertIn("Offline Master Key", sonuc_gero["algoritma"])

        sonuc_toec = sizinti_anahtari_sorgula(".toec")
        self.assertIsNotNone(sonuc_toec)
        self.assertEqual(sonuc_toec["anahtar_hex"], DJVU_GENISLETILMIS_OFFLINE_ANAHTARLAR["toec"])

    def test_bilinen_sizinti_aileleri(self) -> None:
        sonuc_babuk = sizinti_anahtari_sorgula("babuk")
        self.assertIsNotNone(sonuc_babuk)
        self.assertIn("ChaCha20", sonuc_babuk["algoritma"])

        sonuc_conti = sizinti_anahtari_sorgula("conti")
        self.assertIsNotNone(sonuc_conti)

        sonuc_lockbit = sizinti_anahtari_sorgula("lockbit3")
        self.assertIsNotNone(sonuc_lockbit)


if __name__ == "__main__":
    unittest.main()
