from typing import Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend
from rescat.cozuculer.temel_cozucu import TemelCozucu


class ChaChaCozucu(TemelCozucu):
    # chacha20 akış algoritması çözücü sınıfı.
    def __init__(
        self,
        anahtar_baytlari: bytes,
        guvenlik_no: Optional[bytes] = None,
        nonce_dosya_basinda_mi: bool = True,
        kuru_calistirma: bool = False,
        yedek_al: bool = True,
        hedef_cikti_dizini: Optional[str] = None,
        baslatma_vektoru: Optional[bytes] = None
    ) -> None:
        # chacha20 çözücü parametrelerini başlatır.
        super().__init__(
            kuru_calistirma=kuru_calistirma,
            yedek_al=yedek_al,
            hedef_cikti_dizini=hedef_cikti_dizini
        )
        self.anahtar_baytlari: bytes = anahtar_baytlari
        # güvenlik numarası veya iv parametresini kabul eder.
        self.guvenlik_no: Optional[bytes] = guvenlik_no if guvenlik_no is not None else baslatma_vektoru
        self.nonce_dosya_basinda_mi: bool = nonce_dosya_basinda_mi

        if len(self.anahtar_baytlari) != 32:
            raise ValueError("chacha20 anahtari tam olarak 32 bayt olmalidir")

    def baytlari_coz(self, sifreli_baytlar: bytes) -> bytes:
        # chacha20 akışı ile şifreyi çözer.
        kullanilacak_nonce = self.guvenlik_no
        aslinda_sifreli_veri = sifreli_baytlar

        if kullanilacak_nonce is None and self.nonce_dosya_basinda_mi:
            if len(sifreli_baytlar) < 16:
                raise ValueError("veri boyutu nonce icerecek kadar uzun degil")
            kullanilacak_nonce = sifreli_baytlar[:16]
            aslinda_sifreli_veri = sifreli_baytlar[16:]
        elif kullanilacak_nonce is None:
            kullanilacak_nonce = b"\x00" * 16

        # chacha20 16 baytlık nonce bekler.
        if len(kullanilacak_nonce) == 12:
            # ietf 96-bit nonce biçimi.
            kullanilacak_nonce = b"\x00\x00\x00\x00" + kullanilacak_nonce
        elif len(kullanilacak_nonce) < 16:
            kullanilacak_nonce = kullanilacak_nonce.ljust(16, b"\x00")
        elif len(kullanilacak_nonce) > 16:
            kullanilacak_nonce = kullanilacak_nonce[:16]

        algoritma = algorithms.ChaCha20(self.anahtar_baytlari, kullanilacak_nonce)
        sifreleyici = Cipher(algoritma, mode=None, backend=default_backend())
        cozucu_nesne = sifreleyici.decryptor()

        return cozucu_nesne.update(aslinda_sifreli_veri) + cozucu_nesne.finalize()
