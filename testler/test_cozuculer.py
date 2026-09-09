import os
import unittest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from rescat.cozuculer.xor_cozucu import XorCozucu
from rescat.cozuculer.aes_cozucu import AesCozucu
from rescat.cozuculer.chacha_cozucu import ChaChaCozucu
from rescat.cozuculer.rsa_cozucu import RsaCozucu


class TestCozuculer(unittest.TestCase):
    # tum cozucu motorlarini dogrulayan test sinifi
    def test_xor_cozucu(self) -> None:
        # xor cozucunun orijinal veriyi eksiksiz kurtarmasi
        orijinal_veri = b"adli bilisim ve olay mudahale calismasi"
        anahtar = b"GIZLI123"

        sifreli_veri = bytearray(len(orijinal_veri))
        for indeks, bayt in enumerate(orijinal_veri):
            sifreli_veri[indeks] = bayt ^ anahtar[indeks % len(anahtar)]

        cozucu = XorCozucu(anahtar_baytlari=anahtar)
        kurtarilan_veri = cozucu.baytlari_coz(bytes(sifreli_veri))
        self.assertEqual(kurtarilan_veri, orijinal_veri)

    def test_aes_cbc_cozucu(self) -> None:
        # aes cbc algoritmasi ile sifrelenmis verinin cozulmesi
        orijinal_veri = b"Bu veri AES-CBC 256 bit ile guvenli sekilde sifrelenmistir."
        anahtar = os.urandom(32)
        baslatma_vektoru = os.urandom(16)

        dolgu_ekleyici = padding.PKCS7(128).padder()
        dolgulu_veri = dolgu_ekleyici.update(orijinal_veri) + dolgu_ekleyici.finalize()

        sifreleyici = Cipher(algorithms.AES(anahtar), modes.CBC(baslatma_vektoru), backend=default_backend()).encryptor()
        sifreli_bloklar = sifreleyici.update(dolgulu_veri) + sifreleyici.finalize()

        # iv'yi dosyanin basina ekle (ransomware davranisi)
        dosya_verisi = baslatma_vektoru + sifreli_bloklar

        cozucu = AesCozucu(
            anahtar_baytlari=anahtar,
            mod_adi="cbc",
            iv_dosya_basinda_mi=True
        )
        kurtarilan_veri = cozucu.baytlari_coz(dosya_verisi)
        self.assertEqual(kurtarilan_veri, orijinal_veri)

    def test_chacha20_cozucu(self) -> None:
        # chacha20 ile sifrelenmis verinin cozulmesi
        orijinal_veri = b"ChaCha20 ransomware saldirisina karsi kurtarma testi."
        anahtar = os.urandom(32)
        guvenlik_no = os.urandom(16)

        sifreleyici = Cipher(algorithms.ChaCha20(anahtar, guvenlik_no), mode=None, backend=default_backend()).encryptor()
        sifreli_icerik = sifreleyici.update(orijinal_veri) + sifreleyici.finalize()

        # nonce basinda yer alsin
        dosya_verisi = guvenlik_no + sifreli_icerik

        cozucu = ChaChaCozucu(
            anahtar_baytlari=anahtar,
            nonce_dosya_basinda_mi=True
        )
        kurtarilan_veri = cozucu.baytlari_coz(dosya_verisi)
        self.assertEqual(kurtarilan_veri, orijinal_veri)

        # baslatma_vektoru parametresi ve 12-baytlik nonce testi
        ietf_nonce = b"\x01" * 12
        full_16_nonce = b"\x00\x00\x00\x00" + ietf_nonce
        sifreleyici2 = Cipher(algorithms.ChaCha20(anahtar, full_16_nonce), mode=None, backend=default_backend()).encryptor()
        sifreli_icerik2 = sifreleyici2.update(orijinal_veri) + sifreleyici2.finalize()

        cozucu_iv = ChaChaCozucu(
            anahtar_baytlari=anahtar,
            baslatma_vektoru=ietf_nonce,
            nonce_dosya_basinda_mi=False
        )
        kurtarilan2 = cozucu_iv.baytlari_coz(sifreli_icerik2)
        self.assertEqual(kurtarilan2, orijinal_veri)

    def test_rsa_cozucu(self) -> None:
        # rsa ozel anahtari ile anahtar blogu cozme testi
        ozel_anahtar = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        genel_anahtar = ozel_anahtar.public_key()

        pem_verisi = ozel_anahtar.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        orijinal_anahtar_bloğu = b"BU_BIR_OTURUM_AES_ANAHTARIDIR__"
        sifreli_blok = genel_anahtar.encrypt(
            orijinal_anahtar_bloğu,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        cozucu = RsaCozucu(ozel_anahtar_pem=pem_verisi, dolgu_turu="oaep")
        kurtarilan_anahtar = cozucu.baytlari_coz(sifreli_blok)
        self.assertEqual(kurtarilan_anahtar, orijinal_anahtar_bloğu)


if __name__ == "__main__":
    unittest.main()
