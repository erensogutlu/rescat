import os
import shutil
import tempfile
import unittest
from unittest.mock import patch, MagicMock
from rescat.yardimcilar.interaktif import interaktif_sihirbaz_baslat, _arka_planda_calistir, akilli_yol_coz
from rescat.otonom import OtonomKurtarmaMotoru
from rescat.cozuculer.djvu_cozucu import DjvuCozucu
from rescat.cekirdek.djvu_veritabani import VARSAYILAN_OFFLINE_ANAHTAR_HEX
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class TestIkiSecenekAkisi(unittest.TestCase):
    def setUp(self):
        self.gecici_dizin = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.gecici_dizin, ignore_errors=True)

    def test_interaktif_cikis(self):
        # 0 secenegi ile programin guvenle sonlanmasi
        with patch("builtins.input", side_effect=["0"]):
            try:
                interaktif_sihirbaz_baslat()
                tamamlandi = True
            except Exception:
                tamamlandi = False
        self.assertTrue(tamamlandi)

    def test_interaktif_genel_tarama_ve_cozum_akisi(self):
        # 1 secenegi ile genel tarama ve sifre cozumu baslatilmasi
        with patch("builtins.input", side_effect=["1", self.gecici_dizin, "", "0"]):
            with patch("rescat.yardimcilar.interaktif._arka_planda_calistir") as mock_arka_plan:
                interaktif_sihirbaz_baslat()
                self.assertTrue(mock_arka_plan.called)
                motor = mock_arka_plan.call_args[0][0]
                self.assertIsInstance(motor, OtonomKurtarmaMotoru)
                self.assertEqual(motor.hedef_dizin, os.path.abspath(self.gecici_dizin))

    def test_interaktif_ozel_tarama_ve_cozum_akisi(self):
        # 2 secenegi ile ozel tarama ve sifre cozumu baslatilmasi (tekil dosya)
        sahte_dosya = os.path.join(self.gecici_dizin, "onemli.doc.locked")
        with open(sahte_dosya, "wb") as f:
            f.write(b"test" * 50)

        with patch("builtins.input", side_effect=["2", sahte_dosya, "", "0"]):
            with patch("rescat.yardimcilar.interaktif._arka_planda_calistir") as mock_arka_plan:
                interaktif_sihirbaz_baslat()
                self.assertTrue(mock_arka_plan.called)
                motor = mock_arka_plan.call_args[0][0]
                self.assertIsInstance(motor, OtonomKurtarmaMotoru)
                self.assertEqual(motor.tekil_dosya, os.path.abspath(sahte_dosya))

    def test_interaktif_ozel_tarama_dizin_ve_uzanti_filtresi(self):
        # 2 secenegi ile dizin ve uzanti filtresi secimi
        with patch("builtins.input", side_effect=["2", self.gecici_dizin, ".locked", "", "0"]):
            with patch("rescat.yardimcilar.interaktif._arka_planda_calistir") as mock_arka_plan:
                interaktif_sihirbaz_baslat()
                self.assertTrue(mock_arka_plan.called)
                motor = mock_arka_plan.call_args[0][0]
                self.assertEqual(motor.uzanti_filtresi, ".locked")

    def test_otonom_motor_tekil_dosya_cozumu(self):
        # OtonomKurtarmaMotoru'nun tekil bir Stop/Djvu dosyasini otomatik tespit edip cozmesi
        png_sihirli = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x10\x00\x00\x00\x10"
        govde = b"B" * 512
        orijinal_veri = png_sihirli + govde

        anahtar = bytes.fromhex(VARSAYILAN_OFFLINE_ANAHTAR_HEX)
        iv = b"\x00" * 16
        sifreleyici = Cipher(algorithms.AES(anahtar), modes.CBC(iv), backend=default_backend()).encryptor()
        sifreli_blok = sifreleyici.update(orijinal_veri[:16]) + sifreleyici.finalize()
        kurban_isaretcisi = b"abc123def456ghi789jkl012mno345pqrst1"
        sifreli_icerik = sifreli_blok + orijinal_veri[16:] + kurban_isaretcisi

        sifreli_yol = os.path.join(self.gecici_dizin, "foto.png.gero")
        with open(sifreli_yol, "wb") as f:
            f.write(sifreli_icerik)

        motor = OtonomKurtarmaMotoru(hedef=sifreli_yol, kuru_calistirma=False, yedek_al=True)
        sonuc = motor.calistir()

        self.assertTrue(sonuc["basarili"])
        self.assertIn(sifreli_yol, sonuc["sifreli_dosyalar"])
        self.assertTrue(any(c.get("basarili") for c in sonuc["cozulen_dosyalar"]))


class TestInteraktifYardimcilar(unittest.TestCase):
    def test_akilli_yol_coz_bos(self):
        self.assertEqual(akilli_yol_coz(""), "")

    def test_akilli_yol_coz_mevcut_dosya(self):
        mevcut = os.path.abspath(__file__)
        self.assertEqual(akilli_yol_coz(mevcut), mevcut)

    def test_akilli_yol_coz_goreceli(self):
        bu_dosya = "testler/test_iki_secenek_akisi.py"
        beklenen = os.path.abspath(bu_dosya)
        self.assertEqual(akilli_yol_coz(bu_dosya), beklenen)


if __name__ == "__main__":
    unittest.main()
