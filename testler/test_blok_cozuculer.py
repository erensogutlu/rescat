import os
import tempfile
import unittest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from rescat.cozuculer.blok_cozucu import BlokCozucu, DESTEKLENEN_BLOK_ALGORITMALARI


class TestBlokCozuculer(unittest.TestCase):
    def setUp(self):
        self.gecici_dizin = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.gecici_dizin.cleanup()

    def test_blowfish_cozumu(self):
        anahtar = b"BlowfishSecretKey"
        iv = b"12345678"  # 8 bytes block
        duz_metin = b"ABCDEFGH12345678"  # 16 bytes = 2 blocks

        cipher = Cipher(algorithms.Blowfish(anahtar), modes.CBC(iv))
        encryptor = cipher.encryptor()
        sifreli = encryptor.update(duz_metin) + encryptor.finalize()

        cozucu = BlokCozucu(
            algoritma_adi="blowfish",
            anahtar_baytlari=anahtar,
            mod_adi="cbc",
            baslatma_vektoru=iv,
            iv_dosya_basinda_mi=False
        )
        cozulmus = cozucu.baytlari_coz(sifreli)
        self.assertEqual(cozulmus, duz_metin)

    def test_triple_des_cozumu(self):
        anahtar = b"123456781234567812345678"  # 192-bit (24 bytes)
        iv = b"abcdefgh"
        duz_metin = b"TRIPLEDESDATA123"

        cipher = Cipher(algorithms.TripleDES(anahtar), modes.CBC(iv))
        encryptor = cipher.encryptor()
        sifreli = encryptor.update(duz_metin) + encryptor.finalize()

        cozucu = BlokCozucu(
            algoritma_adi="3des",
            anahtar_baytlari=anahtar,
            mod_adi="cbc",
            baslatma_vektoru=iv,
            iv_dosya_basinda_mi=False
        )
        cozulmus = cozucu.baytlari_coz(sifreli)
        self.assertEqual(cozulmus, duz_metin)

    def test_camellia_dosya_cozumu(self):
        anahtar = b"0123456789abcdef"  # 128-bit
        iv = b"1234567890abcdef"       # 16 bytes block
        # PNG sihirli baytı içeren 16 baytlık blok
        duz_veri = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"

        cipher = Cipher(algorithms.Camellia(anahtar), modes.CBC(iv))
        encryptor = cipher.encryptor()
        sifreli = encryptor.update(duz_veri) + encryptor.finalize()

        # Dosya başına IV ekleyelim (iv_dosya_basinda_mi=True)
        dosya_icerigi = iv + sifreli
        hedef_dosya = os.path.join(self.gecici_dizin.name, "resim.png.camellia")
        with open(hedef_dosya, "wb") as f:
            f.write(dosya_icerigi)

        cozucu = BlokCozucu(
            algoritma_adi="camellia",
            anahtar_baytlari=anahtar,
            mod_adi="cbc",
            iv_dosya_basinda_mi=True,
            yedek_al=True
        )
        sonuc = cozucu.tekil_dosya_coz(hedef_dosya)

        self.assertTrue(sonuc.get("basarili"))
        self.assertEqual(sonuc.get("dogrulanan_tur"), "png")

        with open(hedef_dosya, "rb") as f:
            self.assertEqual(f.read(), duz_veri)

    def test_desteklenen_algoritmalar_listesi(self):
        beklenen = ["blowfish", "3des", "cast5", "camellia", "idea", "seed", "sm4"]
        for b in beklenen:
            self.assertIn(b, DESTEKLENEN_BLOK_ALGORITMALARI)


if __name__ == "__main__":
    unittest.main()
