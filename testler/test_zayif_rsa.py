import unittest
from rescat.cekirdek.zayif_rsa import (
    fermat_carpanlara_ayir,
    wiener_saldirisi,
    rsa_ozel_anahtar_pem_olustur
)


class TestZayifRsa(unittest.TestCase):
    # fermat ve wiener zayif rsa kirma testleri
    def test_fermat_saldirisi(self) -> None:
        # birbirine yakin iki asal sayi
        asal_p = 1000000007
        asal_q = 1000000009
        modulus_n = asal_p * asal_q

        sonuc = fermat_carpanlara_ayir(modulus_n, maksimum_adim=1000)
        self.assertIsNotNone(sonuc)
        bulunan_p, bulunan_q = sonuc
        self.assertEqual(sorted([bulunan_p, bulunan_q]), sorted([asal_p, asal_q]))

    def test_wiener_saldirisi(self) -> None:
        # kucuk d degeri icin wiener saldirisi ornegi
        # n = 90581, e = 17993 -> d = 5, p = 379, q = 239
        asal_p = 379
        asal_q = 239
        modulus_n = asal_p * asal_q
        genel_us_e = 17993

        sonuc = wiener_saldirisi(genel_us_e, modulus_n)
        self.assertIsNotNone(sonuc)
        bulunan_d, bulunan_p, bulunan_q = sonuc
        self.assertEqual(bulunan_d, 5)
        self.assertEqual(sorted([bulunan_p, bulunan_q]), sorted([asal_p, asal_q]))

    def test_rsa_pem_olusturma(self) -> None:
        # kurtarilan carpanlardan gecerli pem ozel anahtari uretimi
        asal_p = 61
        asal_q = 53
        pem_anahtar = rsa_ozel_anahtar_pem_olustur(asal_p, asal_q, genel_us_e=17)
        self.assertIn(b"BEGIN PRIVATE KEY", pem_anahtar)


if __name__ == "__main__":
    unittest.main()
