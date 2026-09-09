import unittest
from rescat.analizciler.bellek_anahtar_avcisi import (
    rsa_asal_carpan_rekonstruksiyon,
    zayif_prng_tohum_tara
)


class TestBellekEkKripto(unittest.TestCase):
    """RSA Asal çarpan rekonstrüksiyonu ve PRNG tohum avcısı testleri."""

    def test_rsa_asal_carpan_rekonstruksiyon(self) -> None:
        # Bilinen 2 adet küçük test asalı
        p = 61
        q = 53
        e = 17
        pem = rsa_asal_carpan_rekonstruksiyon(p, q, e=e)
        self.assertIsNotNone(pem)
        self.assertIn("BEGIN PRIVATE KEY", pem)

    def test_zayif_prng_tohum_tara(self) -> None:
        merkez_zaman = 1700000000
        referans_duz_metin = b"%PDF-1.7"

        # Tohum simülasyonu
        durum = merkez_zaman & 0xFFFFFFFF
        uretilen_baytlar = bytearray()
        for _ in range(len(referans_duz_metin)):
            durum = (durum * 214013 + 2531011) & 0xFFFFFFFF
            uretilen_baytlar.append((durum >> 16) & 0xFF)

        sifreli = bytes(referans_duz_metin[i] ^ uretilen_baytlar[i] for i in range(len(referans_duz_metin)))

        sonuc = zayif_prng_tohum_tara(sifreli, referans_duz_metin, merkez_zaman, aralik_saniye=10)
        self.assertIsNotNone(sonuc)
        self.assertTrue(sonuc["basarili"])
        self.assertEqual(sonuc["tohum"], merkez_zaman)


if __name__ == "__main__":
    unittest.main()
