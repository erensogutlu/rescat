import os
import unittest
import tempfile
from rescat.analizciler.footer_ayristirici import FooterAyristirici


class TestFooterAyristirici(unittest.TestCase):
    """Ransomware Footer & Metadata ayrıştırıcı testleri."""

    def test_kurban_id_ve_marker_ayristirma(self) -> None:
        parser = FooterAyristirici()
        govde = b"A" * 500
        footer = b"{12345678-ABCD-1234-ABCD-1234567890AB} LockBit 3.0"
        tam_veri = govde + footer

        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(tam_veri)
            tf_path = tf.name

        try:
            sonuc = parser.dosyayi_ayristir(tf_path)
            self.assertTrue(sonuc["basarili"])
            self.assertIn("{12345678-ABCD-1234-ABCD-1234567890AB}", str(sonuc["kurban_id"]))
            isaretciler = [i["isaretci"] for i in sonuc["bulunan_isaretciler"]]
            self.assertTrue(any("LockBit" in i for i in isaretciler))
        finally:
            if os.path.exists(tf_path):
                os.remove(tf_path)


if __name__ == "__main__":
    unittest.main()
