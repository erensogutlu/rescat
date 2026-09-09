import unittest
import os
import tempfile
from cryptography.hazmat.primitives.asymmetric import x25519
from rescat.analizciler.bellek_anahtar_avcisi import curve25519_anahtar_ara, bellekten_anahtar_ara
from rescat.analizciler.canli_surec_dondurucu import CanliSurecDondurucu


class TestCanliAvciVeX25519Bellek(unittest.TestCase):
    def test_curve25519_bellek_avciligi(self):
        # 1. Gecerli bir Curve25519 anahtar cifti uret (libsodium stili 64 bayt)
        priv = x25519.X25519PrivateKey.generate()
        priv_bytes = priv.private_bytes_raw()
        pub_bytes = priv.public_key().public_bytes_raw()
        libsodium_cifti = priv_bytes + pub_bytes

        # Sahte RAM verisi olustur
        sahte_ram = b"\x00" * 512 + libsodium_cifti + b"\x90" * 512

        # 2. curve25519_anahtar_ara ile bul
        sonuclar = curve25519_anahtar_ara(sahte_ram)
        self.assertGreater(len(sonuclar), 0)
        self.assertEqual(sonuclar[0]["ozel_anahtar_hex"], priv_bytes.hex())
        self.assertEqual(sonuclar[0]["kamu_anahtar_hex"], pub_bytes.hex())
        self.assertTrue(sonuclar[0]["libsodium_cifti_mi"])

        # Genel bellek taramasinda da cikmali
        genel_sonuc = bellekten_anahtar_ara(sahte_ram)
        self.assertIn("x25519_anahtarlari", genel_sonuc)
        self.assertGreater(len(genel_sonuc["x25519_anahtarlari"]), 0)

    def test_canli_surec_tarama_arayuzu(self):
        # Mevcut sistemde calisan supheli surecleri tara fonksiyonu hata firlatmadan donmeli
        supheliler = CanliSurecDondurucu.supheli_surecleri_tara()
        self.assertIsInstance(supheliler, list)


if __name__ == "__main__":
    unittest.main()
