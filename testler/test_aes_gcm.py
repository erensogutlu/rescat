import unittest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from rescat.cozuculer.aes_cozucu import AesCozucu


class TestAesGcm(unittest.TestCase):
    """AES-GCM şifre çözücü ve tag doğrulama testleri."""

    def test_aes_gcm_dogru_desifreleme(self) -> None:
        anahtar = b"\x01" * 32
        iv = b"\x02" * 12
        duz_metin = b"Gizli Belge Icerigi %PDF-1.7 Test Metni 1234567890"

        # GCM ile sifrele
        sifreleyici = Cipher(algorithms.AES(anahtar), modes.GCM(iv), backend=default_backend())
        enc = sifreleyici.encryptor()
        sifreli_govde = enc.update(duz_metin) + enc.finalize()
        tag = enc.tag

        # Standart Zarf: IV (12B) + Ciphertext + Tag (16B)
        tam_sifreli_paket = iv + sifreli_govde + tag

        cozucu = AesCozucu(anahtar_baytlari=anahtar, mod_adi="gcm", baslatma_vektoru=None)
        cozulmus = cozucu.baytlari_coz(tam_sifreli_paket)
        self.assertEqual(cozulmus, duz_metin)

    def test_aes_gcm_gecersiz_tag_hata_verir(self) -> None:
        anahtar = b"\x01" * 32
        iv = b"\x02" * 12
        duz_metin = b"Kritik Dosya Icerigi"

        sifreleyici = Cipher(algorithms.AES(anahtar), modes.GCM(iv), backend=default_backend())
        enc = sifreleyici.encryptor()
        sifreli_govde = enc.update(duz_metin) + enc.finalize()
        bozuk_tag = b"\xFF" * 16

        tam_bozuk_paket = iv + sifreli_govde + bozuk_tag

        cozucu = AesCozucu(anahtar_baytlari=anahtar, mod_adi="gcm", baslatma_vektoru=None)
        with self.assertRaises(ValueError):
            cozucu.baytlari_coz(tam_bozuk_paket)


if __name__ == "__main__":
    unittest.main()
