import os
import tempfile
import unittest
from rescat.cozuculer.salsa20_cozucu import Salsa20Cozucu, salsa20_sifrele_coz


class TestSalsa20Cozucu(unittest.TestCase):
    def setUp(self):
        self.gecici_dizin = tempfile.TemporaryDirectory()
        self.anahtar_32 = b"01234567890123456789012345678901"  # 256-bit
        self.anahtar_16 = b"abcdefghijklmnop"                  # 128-bit
        self.nonce_8 = b"\x01\x02\x03\x04\x05\x06\x07\x08"

    def tearDown(self):
        self.gecici_dizin.cleanup()

    def test_salsa20_256_roundtrip(self):
        duz_metin = b"Salsa20 Stream Cipher Decryption Verification Data 12345"
        sifreli = salsa20_sifrele_coz(self.anahtar_32, self.nonce_8, duz_metin, rounds=20)
        self.assertNotEqual(sifreli, duz_metin)

        cozulmus = salsa20_sifrele_coz(self.anahtar_32, self.nonce_8, sifreli, rounds=20)
        self.assertEqual(cozulmus, duz_metin)

    def test_salsa20_128_roundtrip(self):
        duz_metin = b"128-bit Salsa20 Key Encryption and Decryption Test"
        sifreli = salsa20_sifrele_coz(self.anahtar_16, self.nonce_8, duz_metin, rounds=12)
        cozulmus = salsa20_sifrele_coz(self.anahtar_16, self.nonce_8, sifreli, rounds=12)
        self.assertEqual(cozulmus, duz_metin)

    def test_salsa20_dosya_cozumu_nonce_basinda(self):
        png_verisi = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00"
        sifreli_png = salsa20_sifrele_coz(self.anahtar_32, self.nonce_8, png_verisi)
        # Dosya başına 8 bayt nonce ekleyelim
        dosya_icerigi = self.nonce_8 + sifreli_png

        hedef_dosya = os.path.join(self.gecici_dizin.name, "resim.png.salsa")
        with open(hedef_dosya, "wb") as f:
            f.write(dosya_icerigi)

        cozucu = Salsa20Cozucu(
            anahtar_baytlari=self.anahtar_32,
            nonce_dosya_basinda_mi=True,
            yedek_al=True
        )
        sonuc = cozucu.tekil_dosya_coz(hedef_dosya)

        self.assertTrue(sonuc.get("basarili"))
        self.assertEqual(sonuc.get("dogrulanan_tur"), "png")

        with open(hedef_dosya, "rb") as f:
            self.assertEqual(f.read(), png_verisi)

    def test_salsa20_rfc7938_kat_vector(self):
        # RFC 7938 Salsa20/20 Test Vektörü: 32 sıfır baytı anahtar, 8 sıfır baytı nonce
        anahtar_sifir = bytes(32)
        nonce_sifir = bytes(8)
        duz_metin_sifir = bytes(64)
        # RFC 7938 1. blok keystream
        beklenen_hex = (
            "9a97f65b9b4c721b960a672145fca8d4"
            "e32e67f9111ea979ce9c4826806aeee6"
            "3de9c0da2bd7f91ebcb2639bf989c625"
            "1b29bf38d39a9bdce7c55f4b2ac12a39"
        )
        sifreli = salsa20_sifrele_coz(anahtar_sifir, nonce_sifir, duz_metin_sifir, rounds=20)
        self.assertEqual(sifreli.hex(), beklenen_hex)


if __name__ == "__main__":
    unittest.main()
