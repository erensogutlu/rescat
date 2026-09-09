import unittest
from rescat.cekirdek.bilinen_metin import bilinen_metin_saldirisi_yap, xor_bayt_islemi


class TestBilinenMetin(unittest.TestCase):
    # bilinen metin saldirisi mantigini dogrulayan test sinifi
    def test_xor_anahtar_kurtarma(self) -> None:
        # bilinen metin ve statik anahtar ile sifrelenmis veriden anahtar kurtarma
        orijinal_metin = b"Bu onemli bir sirket belgesidir ve icerigi gizlidir." * 10
        gizli_anahtar = b"KALI2026"

        # gizli anahtarla xor sifrelemesi yap
        sifreli_metin = bytearray(len(orijinal_metin))
        for indeks, bayt in enumerate(orijinal_metin):
            sifreli_metin[indeks] = bayt ^ gizli_anahtar[indeks % len(gizli_anahtar)]

        saldiri_sonucu = bilinen_metin_saldirisi_yap(orijinal_metin, bytes(sifreli_metin))

        self.assertTrue(saldiri_sonucu["statik_xor_mu"])
        self.assertEqual(saldiri_sonucu["tahmin_edilen_periyot"], 8)
        self.assertEqual(saldiri_sonucu["kurtarilan_anahtar_hex"], gizli_anahtar.hex())
        self.assertEqual(saldiri_sonucu["kurtarilan_anahtar_ascii"], "KALI2026")


if __name__ == "__main__":
    unittest.main()
