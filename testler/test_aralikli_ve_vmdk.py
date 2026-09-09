import unittest
import os
import tempfile
from rescat.cekirdek.aralikli_sifre_motoru import AralikliSifreMotoru
from rescat.cekirdek.yapisal_kurtarici import YapisalKurtarmaMotoru


class TestAralikliVeVmdk(unittest.TestCase):
    def setUp(self):
        self.gecici_dizin = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.gecici_dizin.cleanup()

    def test_aralikli_patern_tespiti_ve_cozumu(self):
        # 1. Sentetik bir aralikli sifreli dosya olustur (64 bayt sifreli, 128 bayt acik metin)
        dosya_yolu = os.path.join(self.gecici_dizin.name, "veritabani.sqlite.enc")
        
        # Orijinal icerik
        sqlite_header = b"SQLite format 3\x00" + b"\x04\x00\x01\x01\x00" + (b"A" * 82)
        orijinal_veri = sqlite_header + (b"Normal veritabani tablosu ve yapraklari " * 300)

        # 64B sifreli (yuksek entropi rastgele), 128B acik
        sifreli_veri = bytearray()
        i = 0
        anahtar_xor = 0xAA
        while i < len(orijinal_veri):
            # 64 bayt sifrele (xor ile)
            parca = orijinal_veri[i:i + 64]
            # yuksek entropi icin os.urandom ile sentetik sifre bloklari
            sifreli_veri.extend(bytes([b ^ anahtar_xor for b in parca]))
            i += len(parca)

            # 128 bayt acik birak
            parca_acik = orijinal_veri[i:i + 128]
            sifreli_veri.extend(parca_acik)
            i += len(parca_acik)

        with open(dosya_yolu, "wb") as f:
            f.write(sifreli_veri)

        # 2. Aralikli motor ile coz
        motor = AralikliSifreMotoru(yedek_al=False)
        def basit_cozucu(blok: bytes) -> bytes:
            return bytes([b ^ anahtar_xor for b in blok])

        sonuc = motor.aralikli_dosya_coz(
            dosya_yolu=dosya_yolu,
            cozucu_fonksiyonu=basit_cozucu,
            sifreli_adim=64,
            atlama_adim=128
        )
        self.assertTrue(sonuc.get("basarili"))
        self.assertEqual(sonuc.get("dogrulanan_tur"), "sqlite")

    def test_vmdk_descriptor_rekonstruksiyonu(self):
        # Sahte bir -flat.vmdk olustur (NTFS imzali)
        vmdk_flat = os.path.join(self.gecici_dizin.name, "WindowsServer-flat.vmdk")
        with open(vmdk_flat, "wb") as f:
            # 512 bayt VBR (NTFS) + 1 MB sahte veri
            f.write(b"\xebR\x90NTFS    \x00\x02\x08\x00\x00" + b"\x00" * 500)
            f.write(b"\x90" * (1024 * 1024))

        yapisal = YapisalKurtarmaMotoru(yedek_al=False)
        sonuc = yapisal.vmdk_disk_kurtar(vmdk_flat)

        self.assertTrue(sonuc.get("basarili"))
        self.assertEqual(sonuc.get("format"), "vmdk")
        self.assertIn("NTFS", sonuc.get("tespit_edilen_fs", ""))
        self.assertTrue(os.path.exists(sonuc["hedef_yol"]))

        # Olusturulan descriptor icerigini dogrula
        with open(sonuc["hedef_yol"], "r", encoding="utf-8") as desc_f:
            desc_metin = desc_f.read()
            self.assertIn("# Disk DescriptorFile", desc_metin)
            self.assertIn("WindowsServer-flat.vmdk", desc_metin)


if __name__ == "__main__":
    unittest.main()
