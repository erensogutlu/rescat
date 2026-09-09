import os
import unittest
import tempfile
from rescat.cekirdek.kismi_sifre_motoru import KismiSifreMotoru


class TestKismiSifre(unittest.TestCase):
    """Kısmi / Intermittent / Stride şifreleme motoru testleri."""

    def test_baslik_coz_mantigi(self) -> None:
        motor = KismiSifreMotoru(kuru_calistirma=True)
        # 10 bayt şifreli başlık, 50 bayt sağlam gövde
        orijinal_veri = b"%PDF-1.7" + b"A" * 100
        sifreli_baslik = bytes(b ^ 0xAA for b in orijinal_veri[:16])
        kismi_sifreli_veri = sifreli_baslik + orijinal_veri[16:]

        cozucu_fn = lambda d: bytes(b ^ 0xAA for b in d)
        cozulmus = motor.baslik_coz(kismi_sifreli_veri, 16, cozucu_fn)
        self.assertEqual(cozulmus, orijinal_veri)

    def test_otomatik_kismi_kurtar_dosya(self) -> None:
        motor = KismiSifreMotoru(kuru_calistirma=True)
        orijinal = b"\x89PNG\r\n\x1a\n" + b"\x00" * 200
        sifreli_kisim = bytes(b ^ 0x55 for b in orijinal[:32])
        tam_veri = sifreli_kisim + orijinal[32:]

        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(tam_veri)
            tf_path = tf.name

        try:
            cozucu_fn = lambda d: bytes(b ^ 0x55 for b in d)
            sonuc = motor.otomatik_kismi_kurtar(tf_path, cozucu_fn)
            self.assertTrue(sonuc["basarili"])
            self.assertEqual(sonuc["dogrulanan_tur"].lower(), "png")
        finally:
            if os.path.exists(tf_path):
                os.remove(tf_path)


if __name__ == "__main__":
    unittest.main()
