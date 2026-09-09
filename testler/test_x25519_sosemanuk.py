import unittest
import os
import tempfile
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib

from rescat.cozuculer.x25519_cozucu import X25519HibritCozucu
from rescat.cozuculer.akici_sosemanuk import SosemanukCozucu
from rescat.cozuculer.evrensel_cozucu import CozucuFabrikasi


class TestX25519VeSosemanuk(unittest.TestCase):
    def setUp(self):
        self.gecici_dizin = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.gecici_dizin.cleanup()

    def test_x25519_chacha20_hibrit_cozumu(self):
        # 1. Saldirgan anahtar cifti uret
        saldirgan_ozel = x25519.X25519PrivateKey.generate()
        saldirgan_kamu = saldirgan_ozel.public_key()

        # 2. Kurban makinede efemeral anahtar cifti uret
        kurban_ozel = x25519.X25519PrivateKey.generate()
        kurban_kamu_baytlar = kurban_ozel.public_key().public_bytes_raw()

        # 3. Kurban ortak sir ve simetrik anahtar turetir
        paylasilan_sir = kurban_ozel.exchange(saldirgan_kamu)
        simetrik_anahtar = hashlib.sha256(paylasilan_sir).digest()

        # 4. Dosyayi ChaCha20 ile sifrele
        orijinal_veri = b"%PDF-1.7\n" + b"X25519 Hibrit Kurtarma Test Verisi" * 20
        nonce = b"\x12" * 16
        sifreleyici = Cipher(algorithms.ChaCha20(simetrik_anahtar, nonce), mode=None, backend=default_backend()).encryptor()
        sifreli_icerik = sifreleyici.update(orijinal_veri) + sifreleyici.finalize()

        # Dosya yapisi: 32 bayt kurban kamu anahtari + 16 bayt nonce + sifreli veri
        paketlenmis_dosya = kurban_kamu_baytlar + nonce + sifreli_icerik

        test_dosya = os.path.join(self.gecici_dizin.name, "belge.pdf.lockbit")
        with open(test_dosya, "wb") as f:
            f.write(paketlenmis_dosya)

        # 5. Saldirgan ozel anahtari ele gecirildiginde X25519HibritCozucu ile kurtar
        cozucu = X25519HibritCozucu(
            ozel_anahtar_baytlari=saldirgan_ozel.private_bytes_raw(),
            simetrik_algoritma="chacha20",
            anahtar_konumu="basinda",
            yedek_al=False
        )
        sonuc = cozucu.tekil_dosya_coz(test_dosya)
        self.assertTrue(sonuc.get("basarili"))
        self.assertEqual(sonuc.get("dogrulanan_tur"), "pdf")

    def test_sosemanuk_cozucu_ve_fabrika(self):
        anahtar = b"0123456789abcdef"  # 16 bayt
        iv = b"fedcba9876543210"       # 16 bayt
        orijinal = b"\x89PNG\r\n\x1a\n" + b"Sosemanuk ESXiArgs test verisi" * 10

        cozucu_enc = SosemanukCozucu(anahtar_baytlari=anahtar, baslatma_vektoru=iv)
        sifreli = iv + cozucu_enc.baytlari_coz(orijinal)

        test_dosya = os.path.join(self.gecici_dizin.name, "disk.vmdk.args")
        with open(test_dosya, "wb") as f:
            f.write(sifreli)

        # Fabrika uzerinden cozum
        cozucu_dec = CozucuFabrikasi.cozucu_uret(
            algoritma="sosemanuk",
            anahtar_baytlari=anahtar,
            yedek_al=False
        )
        sonuc = cozucu_dec.tekil_dosya_coz(test_dosya)
        self.assertTrue(sonuc.get("basarili"))
        self.assertEqual(sonuc.get("dogrulanan_tur"), "png")


if __name__ == "__main__":
    unittest.main()
