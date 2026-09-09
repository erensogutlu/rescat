import os
import tempfile
import unittest
import time
from rescat.cekirdek.algoritma_tespit import algoritma_tespit_et
from rescat.cekirdek.zaman_kirici import LcgRastgele


class TestAlgoritmaTespit(unittest.TestCase):
    # algoritma tespit ve siniflandirma motoru birim testleri

    def test_openssl_salted_tespiti(self) -> None:
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b"Salted__" + b"\x12\x34\x56\x78\x9a\xbc\xde\xf0" + b"\xaa" * 64)
            yol = tmp.name

        try:
            tespit = algoritma_tespit_et(yol)
            self.assertTrue(tespit["sifreli_mi"])
            self.assertIn("OpenSSL", tespit["algoritma"])
            self.assertEqual(tespit["kategori"], "STANDART_KRIPTO")
            self.assertGreaterEqual(tespit["guven"], 0.95)
        finally:
            if os.path.exists(yol):
                os.remove(yol)

    def test_wannacry_tespiti(self) -> None:
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b"WANACRY!\x00\x00\x00\x00" + b"\x55" * 128)
            yol = tmp.name

        try:
            tespit = algoritma_tespit_et(yol)
            self.assertTrue(tespit["sifreli_mi"])
            self.assertIn("WannaCry", tespit["algoritma"])
            self.assertEqual(tespit["kategori"], "RANSOMWARE")
        finally:
            if os.path.exists(yol):
                os.remove(yol)

    def test_stop_djvu_tespiti(self) -> None:
        dizin = tempfile.mkdtemp()
        yol = os.path.join(dizin, "belge.docx.gero")
        try:
            icerik = b"\x11" * 128 + b"abc123def456ghi789jkl012mno345pqrst1"
            with open(yol, "wb") as f:
                f.write(icerik)

            tespit = algoritma_tespit_et(yol)
            self.assertTrue(tespit["sifreli_mi"])
            self.assertIn("Stop/Djvu", tespit["algoritma"])
            self.assertEqual(tespit["kategori"], "RANSOMWARE")
            self.assertIn("djvu_offline", tespit["onerilen_cozuculer"])
        finally:
            if os.path.exists(yol):
                os.remove(yol)
            os.rmdir(dizin)

    def test_sifresiz_dosya_tespiti(self) -> None:
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b"%PDF-1.7\n" + b"Normal duz metin PDF dokumani" * 50)
            yol = tmp.name

        try:
            tespit = algoritma_tespit_et(yol)
            self.assertFalse(tespit["sifreli_mi"])
            self.assertEqual(tespit["kategori"], "SIFRESIZ")
        finally:
            if os.path.exists(yol):
                os.remove(yol)

    def test_zaman_tabanli_prng_tespiti(self) -> None:
        tohum = int(time.time()) - 20
        uretec = LcgRastgele(tohum)
        anahtar = uretec.rastgele_baytlar(16)
        duz_pdf = b"%PDF-1.7\n" + b"A" * 64
        sifreli = bytearray(len(duz_pdf))
        for i, b in enumerate(duz_pdf):
            sifreli[i] = b ^ anahtar[i % 16]

        dizin = tempfile.mkdtemp()
        yol = os.path.join(dizin, "test.pdf.enc")
        try:
            with open(yol, "wb") as f:
                f.write(sifreli)
            os.utime(yol, (tohum, tohum))

            tespit = algoritma_tespit_et(yol)
            self.assertTrue(tespit["sifreli_mi"])
            self.assertIn("Zaman-Tabanlı PRNG", tespit["algoritma"])
            self.assertEqual(tespit["kategori"], "ZAYIF_PRNG")
            self.assertIn("zaman_kirici", tespit["onerilen_cozuculer"])
        finally:
            if os.path.exists(yol):
                os.remove(yol)
            os.rmdir(dizin)


    def test_twofish_ve_notpetya_tespiti(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".twofish", delete=False) as tmp:
            tmp.write(os.urandom(256))
            yol = tmp.name
        try:
            tespit = algoritma_tespit_et(yol)
            self.assertTrue(tespit["sifreli_mi"])
            self.assertIn("Twofish", tespit["algoritma"])
            self.assertIn("twofish_cozucu", tespit["onerilen_cozuculer"])
        finally:
            if os.path.exists(yol):
                os.remove(yol)

    def test_salsa20_ve_revil_tespiti(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".sodinokibi", delete=False) as tmp:
            tmp.write(os.urandom(256))
            yol = tmp.name
        try:
            tespit = algoritma_tespit_et(yol)
            self.assertTrue(tespit["sifreli_mi"])
            self.assertIn("REvil", tespit["algoritma"])
            self.assertIn("salsa20_cozucu", tespit["onerilen_cozuculer"])
        finally:
            if os.path.exists(yol):
                os.remove(yol)

    def test_rc4_ve_cerber_tespiti(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".cerber", delete=False) as tmp:
            tmp.write(os.urandom(256))
            yol = tmp.name
        try:
            tespit = algoritma_tespit_et(yol)
            self.assertTrue(tespit["sifreli_mi"])
            self.assertIn("Cerber", tespit["algoritma"])
            self.assertIn("rc4_cozucu", tespit["onerilen_cozuculer"])
        finally:
            if os.path.exists(yol):
                os.remove(yol)

    def test_tea_xtea_tespiti(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".xtea", delete=False) as tmp:
            tmp.write(os.urandom(64))
            yol = tmp.name
        try:
            tespit = algoritma_tespit_et(yol)
            self.assertTrue(tespit["sifreli_mi"])
            self.assertIn("XTEA", tespit["algoritma"])
            self.assertIn("xtea_cozucu", tespit["onerilen_cozuculer"])
        finally:
            if os.path.exists(yol):
                os.remove(yol)

    def test_derin_kriptografik_analiz_raporu(self) -> None:
        from rescat.cekirdek.algoritma_tespit import derin_kriptografik_analiz
        with tempfile.NamedTemporaryFile(suffix=".locked", delete=False) as tmp:
            # 16-bayt bloklu yüksek entropili veri
            tmp.write(os.urandom(512))
            yol = tmp.name
        try:
            rapor = derin_kriptografik_analiz(yol)
            self.assertTrue(rapor["sifreli_mi"])
            self.assertGreaterEqual(rapor["entropi"], 7.2)
            self.assertIn("ki_kare_skoru", rapor)
            self.assertIn("rastgelelik_orani", rapor)
            self.assertEqual(rapor["blok_boyutu"], 16)
            self.assertGreater(len(rapor["aday_algoritmalar"]), 3)

            # Twofish ve AES adaylar arasında bulunmalı
            aday_adlari = [a["algoritma"] for a in rapor["aday_algoritmalar"]]
            self.assertIn("aes", aday_adlari)
            self.assertIn("twofish", aday_adlari)
            self.assertTrue(rapor["komut_onerisi"].startswith("rescat coz"))
        finally:
            if os.path.exists(yol):
                os.remove(yol)

    def test_komut_analiz_calismasi(self) -> None:
        import argparse
        from rescat.ana_komut import komut_analiz
        with tempfile.NamedTemporaryFile(suffix=".locked", delete=False) as tmp:
            tmp.write(os.urandom(256))
            yol = tmp.name
        try:
            ns = argparse.Namespace(hedef=yol, rapor=None, coz=False)
            # komut_analiz hata firlatmadan ciktisini vermeli
            komut_analiz(ns)
        finally:
            if os.path.exists(yol):
                os.remove(yol)


if __name__ == "__main__":
    unittest.main()
