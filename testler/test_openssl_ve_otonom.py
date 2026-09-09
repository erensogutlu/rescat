import unittest
import os
import tempfile
import subprocess
from rescat.cozuculer.openssl_cozucu import OpenSslCozucu
from rescat.otonom import OtonomKurtarmaMotoru


class TestOpenSslVeOtonom(unittest.TestCase):
    def setUp(self):
        self.gecici_dizin = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.gecici_dizin.cleanup()

    def test_openssl_otonom_parola_kurtarma(self):
        # 1. OpenSSL ile sifrelenmis bir dosya olustur (parola: 'test123')
        test_icerik = b"Bu bir gizli rescat test belgesidir.\n" * 5
        kaynak_dosya = os.path.join(self.gecici_dizin.name, "rapor.txt")
        sifreli_dosya = os.path.join(self.gecici_dizin.name, "rapor.txt.enc")

        with open(kaynak_dosya, "wb") as f:
            f.write(test_icerik)

        # OpenSSL CLI ile sifrele
        subprocess.run([
            "openssl", "enc", "-aes-256-cbc", "-salt",
            "-in", kaynak_dosya, "-out", sifreli_dosya,
            "-pass", "pass:test123"
        ], check=True)

        # 2. Otonom motorun dosya adindan/adaylardan 'test123' parolasini otomatik yakalamasi
        motor = OtonomKurtarmaMotoru(
            hedef=sifreli_dosya,
            kuru_calistirma=False,
            yedek_al=False
        )
        sonuc = motor.calistir()
        self.assertTrue(sonuc["basarili"])
        self.assertGreater(len(sonuc["cozulen_dosyalar"]), 0)
        self.assertEqual(sonuc["cozulen_dosyalar"][0].get("dogrulanan_tur"), "txt")


if __name__ == "__main__":
    unittest.main()
