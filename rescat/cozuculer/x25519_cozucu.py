import os
import hashlib
from typing import Optional, Dict, Any
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM
from cryptography.hazmat.backends import default_backend
from rescat.cozuculer.temel_cozucu import TemelCozucu


class X25519HibritCozucu(TemelCozucu):
    """
    curve25519 (x25519) ecdh tabanli hibrit ransomware sifre cozucu.
    lockbit 3.0, akira, babuk, conti ve hive gibi fidye yazilimlarinin
    kullandigi efemeral anahtar degisim mekanizmasini cozer.
    """
    def __init__(
        self,
        ozel_anahtar_baytlari: bytes,
        simetrik_algoritma: str = "chacha20",
        anahtar_konumu: str = "basinda",  # konum belirteci: başında veya sonunda.
        kdf_tipi: str = "sha256",  # kdf türü belirteci.
        kuru_calistirma: bool = False,
        yedek_al: bool = True,
        hedef_cikti_dizini: Optional[str] = None
    ) -> None:
        super().__init__(
            kuru_calistirma=kuru_calistirma,
            yedek_al=yedek_al,
            hedef_cikti_dizini=hedef_cikti_dizini
        )
        if len(ozel_anahtar_baytlari) != 32:
            raise ValueError("X25519 ozel anahtari tam 32 bayt olmalidir.")
        
        self.ozel_anahtar = x25519.X25519PrivateKey.from_private_bytes(ozel_anahtar_baytlari)
        self.simetrik_algoritma = simetrik_algoritma.lower()
        self.anahtar_konumu = anahtar_konumu.lower()
        self.kdf_tipi = kdf_tipi.lower()

    def _ortak_sir_turet(self, karsi_kamu_anahtar_baytlari: bytes) -> bytes:
        """karsi tarafin kamu anahtari ile ortak sir (shared secret) hesaplar"""
        kamu_anahtari = x25519.X25519PublicKey.from_public_bytes(karsi_kamu_anahtar_baytlari)
        ortak_sir = self.ozel_anahtar.exchange(kamu_anahtari)
        
        if self.kdf_tipi == "sha256":
            return hashlib.sha256(ortak_sir).digest()
        elif self.kdf_tipi == "raw":
            return ortak_sir
        elif self.kdf_tipi == "sha512":
            return hashlib.sha512(ortak_sir).digest()[:32]
        return hashlib.sha256(ortak_sir).digest()

    def baytlari_coz(self, sifreli_baytlar: bytes) -> bytes:
        """
        dosya icerisindeki efemeral kamu anahtarini ceker, ortak sirri turetir
        ve simetrik yukude sifreyi acar.
        """
        if len(sifreli_baytlar) < 48:
            raise ValueError("Veri boyutu X25519 basligi ve sifreli govde icin yetersiz.")

        if self.anahtar_konumu == "basinda":
            kurban_kamu_anahtari = sifreli_baytlar[:32]
            govde = sifreli_baytlar[32:]
        else:
            kurban_kamu_anahtari = sifreli_baytlar[-32:]
            govde = sifreli_baytlar[:-32]

        simetrik_anahtar = self._ortak_sir_turet(kurban_kamu_anahtari)

        # simetrik yükte deşifreleme yapar.
        if "chacha" in self.simetrik_algoritma:
            if "poly1305" in self.simetrik_algoritma:
                # 12 bayt nonce ve 16 bayt etiket yapısı.
                nonce = govde[:12]
                sifreli_veri = govde[12:]
                aead = ChaCha20Poly1305(simetrik_anahtar)
                return aead.decrypt(nonce, sifreli_veri, None)
            else:
                # klasik chacha20 yapısı.
                nonce = govde[:16]
                sifreli_veri = govde[16:]
                cozucu = Cipher(algorithms.ChaCha20(simetrik_anahtar, nonce), mode=None, backend=default_backend()).decryptor()
                return cozucu.update(sifreli_veri) + cozucu.finalize()

        elif "gcm" in self.simetrik_algoritma:
            # aes-gcm yapısı.
            iv = govde[:12]
            sifreli_veri = govde[12:]
            aesgcm = AESGCM(simetrik_anahtar)
            return aesgcm.decrypt(iv, sifreli_veri, None)

        else:
            # aes-cbc yapısı.
            iv = govde[:16]
            sifreli_veri = govde[16:]
            cozucu = Cipher(algorithms.AES(simetrik_anahtar), modes.CBC(iv), backend=default_backend()).decryptor()
            ham = cozucu.update(sifreli_veri) + cozucu.finalize()
            # pkcs7 dolgusunu güvenle kaldırır.
            pad_len = ham[-1]
            if 1 <= pad_len <= 16 and ham[-pad_len:] == bytes([pad_len] * pad_len):
                return ham[:-pad_len]
            return ham
