import os
import unittest
import tempfile
from rescat.cekirdek.otonom_algoritma_uretici import OtonomAlgoritmaUretici


class TestOtonomAlgoritmaUretici(unittest.TestCase):
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

    def test_moduler_kaydirma_sentezi_ve_kurtarma(self) -> None:
        # PNG dosyasının baytlarına key eklenmiş olsun: (b + 0x42) % 256
        png_header = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + b"\x00" * 100
        key = 0x42
        sifreli_png = bytes((b + key) % 256 for b in png_header)

        dosya_yolu = os.path.join(self.gecici_dizin, "test_resim.png.custom")
        with open(dosya_yolu, "wb") as f:
            f.write(sifreli_png)

        uretici = OtonomAlgoritmaUretici(hedef_cikti_dizini=self.gecici_dizin)
        sonuc = uretici.algoritma_sentezle_ve_coz(dosya_yolu)

        self.assertTrue(sonuc["basarili"])
        self.assertIn("Dinamik-Modüler-Çıkarma", sonuc["sentezlenen_algoritma"])
        self.assertEqual(sonuc["dogrulanan_tur"], "png")
        self.assertTrue(os.path.exists(sonuc["cikti"]))

        with open(sonuc["cikti"], "rb") as out_f:
            kurtarilan_veri = out_f.read()
        self.assertTrue(kurtarilan_veri.startswith(b"\x89PNG\r\n\x1a\n"))

    def test_bit_rotasyonu_sentezi_ve_kurtarma(self) -> None:
        # PDF dosyasının baytları sola 3 bit rotate edilmiş olsun (ROL 3) -> Çözüm ROR 3
        pdf_header = b"%PDF-1.7\r\n" + b"\x00" * 128
        shift = 3
        sifreli_pdf = bytes(OtonomAlgoritmaUretici._rol8(b, shift) for b in pdf_header)

        dosya_yolu = os.path.join(self.gecici_dizin, "dokuman.pdf.rot")
        with open(dosya_yolu, "wb") as f:
            f.write(sifreli_pdf)

        uretici = OtonomAlgoritmaUretici(hedef_cikti_dizini=self.gecici_dizin)
        sonuc = uretici.algoritma_sentezle_ve_coz(dosya_yolu)

        self.assertTrue(sonuc["basarili"])
        self.assertIn("BitRotasyon-ROR", sonuc["sentezlenen_algoritma"])
        self.assertEqual(sonuc["dogrulanan_tur"], "pdf")

    def test_zarf_siyirma_ve_ofset_rekonstruksiyonu(self) -> None:
        # Ransomware dosyanın başına 256 baytlık özel zarf/header eklemiş olsun
        zip_veri = b"PK\x03\x04\x14\x00\x00\x00" + b"\x00" * 200
        zarf = b"CUSTOM_RANSOMWARE_ENVELOPE_V2\x00" * 8
        zarfli_veri = zarf + zip_veri

        dosya_yolu = os.path.join(self.gecici_dizin, "arsiv.zip.locked")
        with open(dosya_yolu, "wb") as f:
            f.write(zarfli_veri)

        uretici = OtonomAlgoritmaUretici(hedef_cikti_dizini=self.gecici_dizin)
        sonuc = uretici.algoritma_sentezle_ve_coz(dosya_yolu)

        self.assertTrue(sonuc["basarili"])
        self.assertIn("Zarf-Sıyırma", sonuc["sentezlenen_algoritma"])
        self.assertEqual(sonuc["dogrulanan_tur"], "zip")


if __name__ == "__main__":
    unittest.main()
