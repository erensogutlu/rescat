from typing import Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend
from rescat.cozuculer.temel_cozucu import TemelCozucu


class Rc4Cozucu(TemelCozucu):
    # rc4 akış şifre çözücü sınıfı.
    def __init__(
        self,
        anahtar_baytlari: bytes,
        kuru_calistirma: bool = False,
        yedek_al: bool = True,
        hedef_cikti_dizini: Optional[str] = None
    ) -> None:
        super().__init__(
            kuru_calistirma=kuru_calistirma,
            yedek_al=yedek_al,
            hedef_cikti_dizini=hedef_cikti_dizini
        )
        self.anahtar_baytlari: bytes = anahtar_baytlari
        if not (5 <= len(self.anahtar_baytlari) <= 256):
            # rc4 anahtar boyutu 40 ile 2048 bit arasındadır.
            pass

    def baytlari_coz(self, sifreli_baytlar: bytes) -> bytes:
        # rc4 şifreleme ve deşifreleme işlemleri simetriktir.
        try:
            # öncelikle cryptography kütüphanesini dener.
            sifreleyici = Cipher(
                algorithms.ARC4(self.anahtar_baytlari),
                mode=None,
                backend=default_backend()
            )
            cozucu = sifreleyici.decryptor()
            return cozucu.update(sifreli_baytlar) + cozucu.finalize()
        except Exception:
            # saf python ksa ve prga yedek uygulaması.
            return self._saf_rc4(sifreli_baytlar, self.anahtar_baytlari)

    @staticmethod
    def _saf_rc4(veri: bytes, anahtar: bytes) -> bytes:
        # anahtar çizelgeleme algoritması (ksa).
        s = list(range(256))
        j = 0
        anahtar_uzunlugu = len(anahtar)
        for i in range(256):
            j = (j + s[i] + anahtar[i % anahtar_uzunlugu]) % 256
            s[i], s[j] = s[j], s[i]

        # sözde rastgele üretim algoritması (prga).
        i = 0
        j = 0
        sonuc = bytearray(len(veri))
        for idx, b in enumerate(veri):
            i = (i + 1) % 256
            j = (j + s[i]) % 256
            s[i], s[j] = s[j], s[i]
            k = s[(s[i] + s[j]) % 256]
            sonuc[idx] = b ^ k
        return bytes(sonuc)


def saf_python_rc4(anahtar: bytes, veri: bytes) -> bytes:
    # saf python rc4 şifre çözümü.
    return Rc4Cozucu._saf_rc4(veri, anahtar)
