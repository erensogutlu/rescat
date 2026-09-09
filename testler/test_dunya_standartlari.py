import os
import tempfile
import unittest
from rescat.cekirdek.dosya_tanimlayici import (
    sihirli_baytlardan_tur_tahmin_et,
    format_icerik_dogrula,
    ki_kare_yapisal_test
)
from rescat.cekirdek.parola_mutasyon import (
    leet_mutasyonlar,
    kural_tabanli_mutasyon,
    ParalelKiriciMotor
)
from rescat.cozuculer.openssl_cozucu import evp_bytes_to_key
from rescat.analizciler.adli_kurtarma import AdliKurtarmaMotoru
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


class TestDunyaStandartlari(unittest.TestCase):

    def test_genisletilmis_format_ve_kikare(self):
        # 1. Yeni format sihirli basliklari
        self.assertEqual(sihirli_baytlardan_tur_tahmin_et(b"RIFF\x00\x00\x00\x00WEBPVP8"), "webp")
        self.assertEqual(sihirli_baytlardan_tur_tahmin_et(b"RIFF\x00\x00\x00\x00WAVEfmt "), "wav")
        self.assertEqual(sihirli_baytlardan_tur_tahmin_et(b"fLaC\x00\x00\x00"), "flac")
        self.assertEqual(sihirli_baytlardan_tur_tahmin_et(b"\x1aE\xdf\xa3\x01\x00"), "mkv")
        self.assertEqual(sihirli_baytlardan_tur_tahmin_et(b"BZh91AY&SY"), "bzip2")
        self.assertEqual(sihirli_baytlardan_tur_tahmin_et(b"\xfd7zXZ\x00\x00"), "xz")

        # 2. Format icerik dogrulama
        gecerli, tur = format_icerik_dogrula(b"fLaC\x00\x00\x00" + b"\x00"*200)
        self.assertTrue(gecerli)
        self.assertEqual(tur, "flac")

        # 3. Ki-Kare testi: sifreli rastgele gurultu vs yapisal binary veri
        # Sifreli gurultu (tamamen rastgele yuksek entropi)
        rastgele_gurultu = os.urandom(1024)
        # Yapisal binary veri (siklikla 0x00 dolgusu ve pointer iceren ozel veri tabani)
        yapisal_veri = (b"\x00" * 32 + b"\x01\x00\x00\x00" + b"INDEX_DATA" + b"\x00" * 16) * 16

        self.assertTrue(ki_kare_yapisal_test(yapisal_veri))
        # Rastgele gurultu yapisal olarak gecmemeli
        self.assertFalse(ki_kare_yapisal_test(rastgele_gurultu))

    def test_parola_mutasyon_ve_paralel_kirici(self):
        # 1. Leet mutasyonlari
        mutlar = leet_mutasyonlar("admin")
        self.assertTrue(any("4" in m or "@" in m for m in mutlar))

        # 2. Kural tabanli mutasyon
        kural_adaylar = kural_tabanli_mutasyon(["test"], max_toplam=50)
        self.assertTrue(any("test123" in m or "7" in m for m in kural_adaylar))

        # 3. Paralel kirici ile OpenSSL kirma
        salt = b"87654321"
        key, iv = evp_bytes_to_key(b"admin123", salt, 32, 16, "sha256")
        padder = padding.PKCS7(128).padder()
        padded = padder.update(b"%PDF-1.7\nSample PDF payload for decryptor testing.\n") + padder.finalize()
        encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        ct = encryptor.update(padded) + encryptor.finalize()
        sifreli = b"Salted__" + salt + ct

        kirici = ParalelKiriciMotor(islemci_sayisi=2)
        sonuc = kirici.openssl_paralel_kir(
            sifreli,
            adaylar=["yanlis", "test", "admin123", "password"],
            algoritmalar=("aes-256-cbc",)
        )
        self.assertIsNotNone(sonuc)
        kazanan_p, kazanan_algo, cozulen = sonuc
        self.assertEqual(kazanan_p, "admin123")
        self.assertTrue(cozulen.startswith(b"%PDF-1.7"))

    def test_adli_kurtarma_motoru(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Gecici ofis artik dosyasi simule et
            gecici_ofis = os.path.join(tmpdir, "~$gizli_rapor.docx")
            with open(gecici_ofis, "wb") as f:
                f.write(b"PK\x03\x04" + b"\x00" * 128)

            # SQLite WAL simule et
            wal_dosya = os.path.join(tmpdir, "veritabani.sqlite-wal")
            with open(wal_dosya, "wb") as f:
                f.write(b"\x37\x7f\x06\x82" + b"\x00" * 128)

            motor = AdliKurtarmaMotoru(cikti_dizini=os.path.join(tmpdir, "cikti"))
            rapor = motor.tam_adli_kurtarma_yurut(os.path.join(tmpdir, "veritabani.sqlite"))

            self.assertGreaterEqual(len(rapor["gecici_ofis_artiklari"]), 1)
            self.assertGreaterEqual(len(rapor["sqlite_loglari"]), 1)
            self.assertGreaterEqual(rapor["toplam_kurtarilabilir_oge"], 2)


if __name__ == "__main__":
    unittest.main()
