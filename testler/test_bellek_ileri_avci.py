import os
import random
import unittest
from rescat.analizciler.bellek_anahtar_avcisi import (
    chacha20_matris_ara,
    salsa20_matris_ara,
    tea_delta_ve_anahtar_ara,
    rc4_sbox_ara,
    bellekten_anahtar_ara
)


class TestBellekIleriAvci(unittest.TestCase):
    """
    Bellek dökümlerinden ChaCha20, Salsa20, TEA, RC4, DER RSA ve AES avcılığı testleri.
    """

    def test_chacha20_durum_matrisi_yakalama(self) -> None:
        sabit = b"expand 32-byte k"
        orijinal_anahtar = b"\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x00" * 2
        sayac_ve_nonce = b"\x01\x00\x00\x00" + b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb"
        chacha_blogu = sabit + orijinal_anahtar + sayac_ve_nonce

        sahte_ram = os.urandom(512) + chacha_blogu + os.urandom(512)

        bulunanlar = chacha20_matris_ara(sahte_ram)
        self.assertGreaterEqual(len(bulunanlar), 1)
        self.assertEqual(bulunanlar[0]["anahtar_hex"], orijinal_anahtar.hex())
        self.assertEqual(bulunanlar[0]["tur"], "ChaCha20-256")

        genel_sonuc = bellekten_anahtar_ara(sahte_ram)
        self.assertIn("chacha20_anahtarlari", genel_sonuc)
        self.assertGreaterEqual(len(genel_sonuc["chacha20_anahtarlari"]), 1)

    def test_salsa20_durum_matrisi_yakalama(self) -> None:
        # Salsa20 32-bayt anahtar durumu (64 bayt):
        # 0..4: b"expa", 4..20: k1 (16B), 20..24: b"nd 3", 24..32: nonce (8B),
        # 32..40: counter (8B), 40..44: b"2-by", 44..60: k2 (16B), 60..64: b"te k"
        k1 = b"\x12\x34\x56\x78\x9a\xbc\xde\xf0\x11\x22\x33\x44\x55\x66\x77\x88"
        k2 = b"\xfe\xdc\xba\x98\x76\x54\x32\x10\xaa\xbb\xcc\xdd\xee\xff\x00\x11"
        nonce = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        sayac = b"\x00\x00\x00\x00\x00\x00\x00\x01"

        salsa_blogu = b"expa" + k1 + b"nd 3" + nonce + sayac + b"2-by" + k2 + b"te k"
        sahte_ram = os.urandom(256) + salsa_blogu + os.urandom(256)

        bulunanlar = salsa20_matris_ara(sahte_ram)
        self.assertGreaterEqual(len(bulunanlar), 1)
        self.assertEqual(bulunanlar[0]["tur"], "Salsa20-256")
        self.assertEqual(bulunanlar[0]["anahtar_hex"], (k1 + k2).hex())
        self.assertEqual(bulunanlar[0]["nonce_hex"], nonce.hex())

        # bellekten_anahtar_ara üzerinden de teyit
        genel = bellekten_anahtar_ara(sahte_ram)
        self.assertIn("salsa20_anahtarlari", genel)
        self.assertGreaterEqual(len(genel["salsa20_anahtarlari"]), 1)

    def test_tea_delta_anahtar_yakalama(self) -> None:
        delta = b"\xb9\x79\x37\x9e"  # 0x9E3779B9
        tea_anahtar = b"\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10"
        sahte_ram = b"\x00" * 64 + delta + b"\x00" * 16 + tea_anahtar + b"\x00" * 64

        bulunanlar = tea_delta_ve_anahtar_ara(sahte_ram)
        self.assertGreaterEqual(len(bulunanlar), 1)
        self.assertTrue(any(b["anahtar_hex"] == tea_anahtar.hex() for b in bulunanlar))

    def test_rc4_sbox_yakalama(self) -> None:
        perm = list(range(256))
        random.seed(42)
        random.shuffle(perm)
        sbox_bayt = bytes(perm)
        sahte_ram = os.urandom(128) + sbox_bayt + os.urandom(128)

        bulunanlar = rc4_sbox_ara(sahte_ram)
        self.assertGreaterEqual(len(bulunanlar), 1)
        self.assertEqual(bulunanlar[0]["tur"], "RC4-SBox-Permutasyonu")

    def test_bellek_pem_anahtar_avcisi(self) -> None:
        sahte_pem = b"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----"
        sahte_bellek_dokumu = os.urandom(1024) + sahte_pem + os.urandom(1024)

        tarama_sonucu = bellekten_anahtar_ara(sahte_bellek_dokumu)
        self.assertEqual(tarama_sonucu["rsa_anahtar_sayisi"], 1)
        self.assertIn("BEGIN RSA PRIVATE KEY", tarama_sonucu["rsa_anahtarlari"][0])


if __name__ == "__main__":
    unittest.main()

