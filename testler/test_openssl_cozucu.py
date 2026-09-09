import os
import tempfile
import unittest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from rescat.cozuculer.openssl_cozucu import OpenSslCozucu, evp_bytes_to_key


class TestOpenSslCozucu(unittest.TestCase):
    def setUp(self):
        self.gecici_dizin = tempfile.TemporaryDirectory()
        self.parola = b"SuperOpenSslPassword"
        self.tuz = b"12345678"

    def tearDown(self):
        self.gecici_dizin.cleanup()

    def test_openssl_salted_cozumu(self):
        # OpenSSL EVP sha256 ile anahtar ve IV türetelim
        anahtar, iv = evp_bytes_to_key(self.parola, self.tuz, 32, 16, "sha256")
        duz_veri = b"%PDF-1.5\nOpenSSL Decryption Verified Test"

        padder = padding.PKCS7(128).padder()
        dolgulu = padder.update(duz_veri) + padder.finalize()

        cipher = Cipher(algorithms.AES(anahtar), modes.CBC(iv))
        encryptor = cipher.encryptor()
        sifreli_govde = encryptor.update(dolgulu) + encryptor.finalize()

        openssl_dosyasi = b"Salted__" + self.tuz + sifreli_govde

        hedef_dosya = os.path.join(self.gecici_dizin.name, "belge.pdf.enc")
        with open(hedef_dosya, "wb") as f:
            f.write(openssl_dosyasi)

        cozucu = OpenSslCozucu(parola_veya_anahtar=self.parola, yedek_al=True)
        sonuc = cozucu.tekil_dosya_coz(hedef_dosya)

        self.assertTrue(sonuc.get("basarili"))
        self.assertEqual(sonuc.get("dogrulanan_tur"), "pdf")

        with open(hedef_dosya, "rb") as f:
            self.assertEqual(f.read(), duz_veri)


if __name__ == "__main__":
    unittest.main()
