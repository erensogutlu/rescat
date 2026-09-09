import unittest
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from rescat.cozuculer.poly1305_cozucu import Poly1305Cozucu
from rescat.cozuculer.evrensel_cozucu import CozucuFabrikasi


class TestChaChaPoly1305(unittest.TestCase):
    """ChaCha20-Poly1305 AEAD şifre çözücü testleri."""

    def test_poly1305_zarf_cozumu(self) -> None:
        anahtar = b"\x42" * 32
        nonce = b"\x07" * 12
        duz_metin = b"PK\x03\x04\x14\x00\x00\x00 Gizli ZIP Arsivi Test Payload 12345678"

        aead = ChaCha20Poly1305(anahtar)
        sifreli_ve_tag = aead.encrypt(nonce, duz_metin, None)
        tam_dosya = nonce + sifreli_ve_tag

        cozucu = Poly1305Cozucu(anahtar_baytlari=anahtar)
        cozulmus = cozucu.baytlari_coz(tam_dosya)
        self.assertEqual(cozulmus, duz_metin)

    def test_evrensel_fabrika_poly1305_tanima(self) -> None:
        anahtar = b"\x33" * 32
        cozucu = CozucuFabrikasi.cozucu_uret("chachapoly1305", anahtar)
        self.assertIsInstance(cozucu, Poly1305Cozucu)


if __name__ == "__main__":
    unittest.main()
