import os
import tempfile
import struct
import unittest
from rescat.cozuculer.tea_cozucu import (
    TeaCozucu,
    XteaCozucu,
    XxteaCozucu,
    _tea_blok_sifrele,
    _xtea_blok_sifrele
)


class TestTeaAilesi(unittest.TestCase):
    def setUp(self):
        self.gecici_dizin = tempfile.TemporaryDirectory()
        self.anahtar = b"0123456789abcdef"  # 128-bit = 16 bytes
        self.k = list(struct.unpack(">4I", self.anahtar))

    def tearDown(self):
        self.gecici_dizin.cleanup()

    def test_tea_ecb_roundtrip(self):
        blok = b"ABCDEFGH"  # 8 bytes = 64-bit
        v0, v1 = struct.unpack(">2I", blok)
        sv0, sv1 = _tea_blok_sifrele(v0, v1, self.k)
        sifreli_blok = struct.pack(">2I", sv0, sv1)

        cozucu = TeaCozucu(anahtar_baytlari=self.anahtar, mod_adi="ecb")
        cozulmus = cozucu.baytlari_coz(sifreli_blok)
        self.assertEqual(cozulmus, blok)

    def test_xtea_ecb_roundtrip(self):
        blok = b"12345678"
        v0, v1 = struct.unpack(">2I", blok)
        sv0, sv1 = _xtea_blok_sifrele(v0, v1, self.k)
        sifreli_blok = struct.pack(">2I", sv0, sv1)

        cozucu = XteaCozucu(anahtar_baytlari=self.anahtar, mod_adi="ecb")
        cozulmus = cozucu.baytlari_coz(sifreli_blok)
        self.assertEqual(cozulmus, blok)

    def test_tea_dosya_cozumu(self):
        # 8 bayt katı olan bir ZIP dosya başlığı testi
        duz_veri = b"PK\x03\x04\x14\x00\x00\x00"  # 8 bytes
        v0, v1 = struct.unpack(">2I", duz_veri)
        sv0, sv1 = _tea_blok_sifrele(v0, v1, self.k)
        sifreli_veri = struct.pack(">2I", sv0, sv1)

        hedef_dosya = os.path.join(self.gecici_dizin.name, "arsiv.zip.tea")
        with open(hedef_dosya, "wb") as f:
            f.write(sifreli_veri)

        cozucu = TeaCozucu(anahtar_baytlari=self.anahtar, mod_adi="ecb", yedek_al=True)
        sonuc = cozucu.tekil_dosya_coz(hedef_dosya)

        self.assertTrue(sonuc.get("basarili"))
        self.assertEqual(sonuc.get("dogrulanan_tur"), "zip")

        with open(hedef_dosya, "rb") as f:
            self.assertEqual(f.read(), duz_veri)

    def test_xxtea_cozucu_kisa_veri(self):
        cozucu = XxteaCozucu(anahtar_baytlari=self.anahtar)
        kisa_veri = b"1234"
        # 8 bayttan kısa veri olduğu gibi döner
        self.assertEqual(cozucu.baytlari_coz(kisa_veri), kisa_veri)

    def test_xxtea_cozucu_vektor(self):
        cozucu = XxteaCozucu(anahtar_baytlari=self.anahtar)
        veri = b"0123456789abcdef"
        cozulmus = cozucu.baytlari_coz(veri)
        self.assertIsInstance(cozulmus, bytes)


if __name__ == "__main__":
    unittest.main()
