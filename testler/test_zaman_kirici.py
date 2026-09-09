import time
import unittest
from rescat.cekirdek.zaman_kirici import LcgRastgele, zaman_tabanli_xor_kir


class TestZamanKirici(unittest.TestCase):
    # zaman tabanli tohum ve xor kirici testleri
    def test_zaman_tabanli_kirma_basarili(self) -> None:
        # bilinen bir zamanda tohumlanan lcg xor sifresini cozme
        orijinal_pdf_basligi = b"%PDF-1.7\n" + b"A" * 50
        gercek_zaman = 1700000000

        # gercek tohumla anahtar uret ve sifrele
        uretec = LcgRastgele(gercek_zaman)
        anahtar = uretec.rastgele_baytlar(16)

        sifreli_baytlar = bytearray(len(orijinal_pdf_basligi))
        for i, b in enumerate(orijinal_pdf_basligi):
            sifreli_baytlar[i] = b ^ anahtar[i % 16]

        # +/- 100 saniyelik aralikta tohumu kir
        sonuc = zaman_tabanli_xor_kir(
            bytes(sifreli_baytlar),
            merkez_zaman=gercek_zaman + 25,  # 25 saniye kaymis merkez
            aralik_saniye=50,
            anahtar_uzunlugu=16,
            beklenen_uzanti="pdf"
        )

        self.assertIsNotNone(sonuc)
        self.assertTrue(sonuc["basarili"])
        self.assertEqual(sonuc["kurtarilan_tohum"], gercek_zaman)
        self.assertEqual(sonuc["anahtar_hex"], anahtar.hex())
        self.assertEqual(sonuc["kurtarilan_anahtar_hex"], anahtar.hex())

    def test_zaman_tabanli_kirma_arama_yaricapi_ve_dosya_yolu(self) -> None:
        # arama_yaricapi_saniye keyword argumani ve dosya yolu uzerinden kirma
        import os
        import tempfile
        orijinal_png_basligi = b"\x89PNG\r\n\x1a\n" + b"B" * 50
        gercek_zaman = 1710000000

        uretec = LcgRastgele(gercek_zaman)
        anahtar = uretec.rastgele_baytlar(16)

        sifreli_baytlar = bytearray(len(orijinal_png_basligi))
        for i, b in enumerate(orijinal_png_basligi):
            sifreli_baytlar[i] = b ^ anahtar[i % 16]

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(sifreli_baytlar)
            tmp_yol = tmp.name

        try:
            # arama_yaricapi_saniye keyword argumani ve dosya yolu ile cagri testi
            sonuc = zaman_tabanli_xor_kir(
                tmp_yol,
                merkez_zaman=gercek_zaman - 10,
                arama_yaricapi_saniye=30,
                anahtar_uzunlugu=16,
                beklenen_uzanti="png"
            )
            self.assertIsNotNone(sonuc)
            self.assertTrue(sonuc["basarili"])
            self.assertEqual(sonuc["kurtarilan_tohum"], gercek_zaman)
            self.assertEqual(sonuc["anahtar_hex"], anahtar.hex())
            self.assertEqual(sonuc["kurtarilan_anahtar_hex"], anahtar.hex())
            self.assertEqual(sonuc["dogrulanan_tur"], "png")
        finally:
            if os.path.exists(tmp_yol):
                os.remove(tmp_yol)


if __name__ == "__main__":
    unittest.main()
