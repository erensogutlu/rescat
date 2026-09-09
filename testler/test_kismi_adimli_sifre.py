import unittest
import os
import shutil
import tempfile
from rescat.cekirdek.kismi_sifre_motoru import KismiSifreMotoru


class TestKismiAdimliSifre(unittest.TestCase):

    def setUp(self):
        self.gecici_dizin = tempfile.mkdtemp()
        self.motor = KismiSifreMotoru(kuru_calistirma=False)

    def tearDown(self):
        if os.path.exists(self.gecici_dizin):
            shutil.rmtree(self.gecici_dizin)

    def test_periyodik_adim_profili_ve_adimli_cozum(self):
        # 4096 bayt yüksek entropili rastgele veri + 4096 bayt düşük entropili düz veri
        sifreli_adim = os.urandom(4096)
        duz_adim = b"A" * 4096

        sentetik_veri = (sifreli_adim + duz_adim) * 4

        profil = self.motor.periyodik_adim_profili_cikar(sentetik_veri, blok_boyutu=4096)
        self.assertTrue(profil.get("tespit_edildi"))
        self.assertEqual(profil.get("sifreli_adim"), 4096)
        self.assertEqual(profil.get("atlama_adimi"), 4096)

        # Basit XOR çözücü simülasyonu
        anahtar = 0x55
        orijinal_baslik = b"%PDF-1.7\n" + b"\x00" * 4087
        sifreli_ilk_blok = bytes(b ^ anahtar for b in orijinal_baslik)
        tam_sifreli = sifreli_ilk_blok + duz_adim

        dosya_yolu = os.path.join(self.gecici_dizin, "belge.pdf.locked")
        with open(dosya_yolu, "wb") as f:
            f.write(tam_sifreli)

        def cozucu_fn(veri: bytes) -> bytes:
            return bytes(b ^ anahtar for b in veri)

        sonuc = self.motor.otomatik_kismi_kurtar(dosya_yolu, cozucu_fn)
        self.assertTrue(sonuc.get("basarili"))
        self.assertEqual(sonuc.get("dogrulanan_tur"), "pdf")


if __name__ == "__main__":
    unittest.main()
