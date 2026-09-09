import os
import unittest
import tempfile
from rescat.cekirdek.lokal_ai_motoru import LokalYapayZekaMotoru


class TestLokalYapayZekaMotoru(unittest.TestCase):
    def setUp(self) -> None:
        self.gecici_dizin = tempfile.mkdtemp()

    def tearDown(self) -> None:
        if os.path.exists(self.gecici_dizin):
            for dosya in os.listdir(self.gecici_dizin):
                try:
                    os.remove(os.path.join(self.gecici_dizin, dosya))
                except Exception:
                    pass
            try:
                os.rmdir(self.gecici_dizin)
            except Exception:
                pass

    def test_genetik_kriptanaliz_ile_sifre_cozumu(self) -> None:
        # Polialfabetik 3-baytlık özel bir anahtarla XOR'lanmış XML / Metin dosyası
        orijinal_metin = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<root><data>Secret Forensic Evidence Data</data></root>\n" * 4
        anahtar = b"\x13\x37\x42"
        sifreli = bytes(b ^ anahtar[i % len(anahtar)] for i, b in enumerate(orijinal_metin))

        dosya_yolu = os.path.join(self.gecici_dizin, "belge.xml.enc")
        with open(dosya_yolu, "wb") as f:
            f.write(sifreli)

        ai_motor = LokalYapayZekaMotoru(
            hedef_cikti_dizini=self.gecici_dizin,
            populasyon_boyutu=30,
            jenerasyon_sayisi=40
        )
        sonuc = ai_motor.yapay_zeka_ile_coz(dosya_yolu)

        self.assertTrue(sonuc.get("basarili"))
        self.assertIn("Yapay-Zeka-Genetik-Evrim", sonuc.get("sentezlenen_algoritma", ""))
        self.assertEqual(sonuc.get("dogrulanan_tur"), "xml")

        with open(sonuc["cikti"], "rb") as out_f:
            cozulmus = out_f.read()
        self.assertEqual(cozulmus, orijinal_metin)


if __name__ == "__main__":
    unittest.main()
