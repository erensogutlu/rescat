import unittest
import os
import shutil
import tempfile
import struct
from rescat.cekirdek.yapisal_kurtarici import YapisalKurtarmaMotoru


class TestYapisalMedya(unittest.TestCase):

    def setUp(self):
        self.gecici_dizin = tempfile.mkdtemp()
        self.motor = YapisalKurtarmaMotoru(kuru_calistirma=False, cikti_dizini=self.gecici_dizin)

    def tearDown(self):
        if os.path.exists(self.gecici_dizin):
            shutil.rmtree(self.gecici_dizin)

    def test_mp4_moov_atom_kurtarma(self):
        # Sentetik başlığı bozulmuş / şifrelenmiş MP4 video
        bozuk_baslik = os.urandom(1024)
        mdat_veri = b"\x00\x00\x04\x00mdat" + b"\xAA" * 1016
        moov_govde = b"moov" + b"\xBB" * 256
        moov_atom = struct.pack(">I", len(moov_govde) + 4) + moov_govde

        tam_veri = bozuk_baslik + mdat_veri + moov_atom
        dosya_yolu = os.path.join(self.gecici_dizin, "video.mp4.locked")
        with open(dosya_yolu, "wb") as f:
            f.write(tam_veri)

        sonuc = self.motor.mp4_video_kurtar(dosya_yolu)
        self.assertTrue(sonuc.get("basarili"))
        self.assertTrue(os.path.exists(sonuc["cikti_dosya"]))

        with open(sonuc["cikti_dosya"], "rb") as rf:
            kurtarilan = rf.read()
        self.assertTrue(kurtarilan.startswith(b"\x00\x00\x00\x20ftypisom"))
        self.assertIn(b"moov", kurtarilan)
        self.assertIn(b"mdat", kurtarilan)

    def test_jpeg_sos_baslik_kurtarma(self):
        # Sentetik ilk 64 baytı şifrelenmiş JPEG
        sifreli_baslik = os.urandom(64)
        dqt_ve_scan = b"\xFF\xDB\x00C" + os.urandom(65) + b"\xFF\xDA\x00\x08" + os.urandom(256) + b"\xFF\xD9"
        tam_veri = sifreli_baslik + dqt_ve_scan

        dosya_yolu = os.path.join(self.gecici_dizin, "fotograf.jpg.locked")
        with open(dosya_yolu, "wb") as f:
            f.write(tam_veri)

        sonuc = self.motor.jpeg_resim_kurtar(dosya_yolu)
        self.assertTrue(sonuc.get("basarili"))
        self.assertTrue(os.path.exists(sonuc["cikti_dosya"]))

        with open(sonuc["cikti_dosya"], "rb") as rf:
            kurtarilan = rf.read()
        self.assertTrue(kurtarilan.startswith(b"\xFF\xD8\xFF\xE0"))
        self.assertTrue(kurtarilan.endswith(b"\xFF\xD9"))

    def test_otonom_medya_yonlendirme(self):
        # Uzantıya göre otonom yönlendirme testi
        dosya_mp4 = os.path.join(self.gecici_dizin, "klip.mp4")
        moov_atom = struct.pack(">I", 32) + b"moov" + b"\x00" * 24
        with open(dosya_mp4, "wb") as f:
            f.write(os.urandom(256) + moov_atom)

        sonuc = self.motor.otonom_yapisal_kurtar(dosya_mp4)
        self.assertTrue(sonuc.get("basarili"))


if __name__ == "__main__":
    unittest.main()
