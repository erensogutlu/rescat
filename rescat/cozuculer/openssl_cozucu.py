import hashlib
from typing import Optional, Tuple
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from rescat.cozuculer.temel_cozucu import TemelCozucu


def evp_bytes_to_key(parola: bytes, tuz: bytes, anahtar_len: int = 32, iv_len: int = 16, hash_algoritmasi="md5") -> Tuple[bytes, bytes]:
    # openssl evp_bytestokey türetim fonksiyonu.
    d = b""
    d_i = b""
    while len(d) < (anahtar_len + iv_len):
        h = hashlib.new(hash_algoritmasi)
        h.update(d_i + parola + tuz)
        d_i = h.digest()
        d += d_i
    return d[:anahtar_len], d[anahtar_len:anahtar_len + iv_len]


def pbkdf2_turetim(parola: bytes, tuz: bytes, anahtar_len: int = 32, iv_len: int = 16, iterasyon: int = 10000) -> Tuple[bytes, bytes]:
    # openssl pbkdf2 anahtar ve iv türetimi.
    anahtar_ve_iv = hashlib.pbkdf2_hmac("sha256", parola, tuz, iterasyon, dklen=anahtar_len + iv_len)
    return anahtar_ve_iv[:anahtar_len], anahtar_ve_iv[anahtar_len:anahtar_len + iv_len]


class OpenSslCozucu(TemelCozucu):
    # openssl salted aes çözücü.
    def __init__(
        self,
        parola_veya_anahtar: bytes,
        algoritma_adi: str = "aes-256-cbc",
        kuru_calistirma: bool = False,
        yedek_al: bool = True,
        hedef_cikti_dizini: Optional[str] = None
    ) -> None:
        super().__init__(kuru_calistirma=kuru_calistirma, yedek_al=yedek_al, hedef_cikti_dizini=hedef_cikti_dizini)
        if isinstance(parola_veya_anahtar, str):
            self.parola_veya_anahtar = parola_veya_anahtar.encode("utf-8")
        else:
            self.parola_veya_anahtar = parola_veya_anahtar
        self.algoritma_adi = algoritma_adi.lower()

    def baytlari_coz(self, sifreli_baytlar: bytes) -> bytes:
        if not sifreli_baytlar.startswith(b"Salted__") or len(sifreli_baytlar) < 16:
            # salted başlığı yoksa olduğu gibi döndürür.
            return sifreli_baytlar

        tuz = sifreli_baytlar[8:16]
        govde = sifreli_baytlar[16:]

        anahtar_len = 32 if "256" in self.algoritma_adi else 16
        iv_len = 16

        # sırasıyla anahtar türetim yöntemlerini dener:
        # 1. sha256 evp türetimi.
        # 2. md5 evp türetimi.
        # 3. pbkdf2-sha256 türetimi.
        turetimler = [
            evp_bytes_to_key(self.parola_veya_anahtar, tuz, anahtar_len, iv_len, "sha256"),
            evp_bytes_to_key(self.parola_veya_anahtar, tuz, anahtar_len, iv_len, "md5"),
            pbkdf2_turetim(self.parola_veya_anahtar, tuz, anahtar_len, iv_len)
        ]

        en_iyi_cozum = b""

        for k, iv in turetimler:
            try:
                sifreleyici = Cipher(algorithms.AES(k), modes.CBC(iv), backend=default_backend())
                cozucu = sifreleyici.decryptor()
                ham = cozucu.update(govde) + cozucu.finalize()
                ayiklayici = padding.PKCS7(128).unpadder()
                cozulmus = ayiklayici.update(ham) + ayiklayici.finalize()

                # sihirli bayt doğrulaması.
                tur = self.cozulen_veriyi_dogrula(cozulmus)
                if tur:
                    return cozulmus
            except Exception:
                continue

        return sifreli_baytlar
