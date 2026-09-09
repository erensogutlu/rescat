from typing import Optional
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from rescat.cozuculer.temel_cozucu import TemelCozucu


class RsaCozucu(TemelCozucu):
    # rsa özel anahtarı ile şifre çözücü sınıf.
    def __init__(
        self,
        ozel_anahtar_pem: bytes,
        parola: Optional[bytes] = None,
        dolgu_turu: str = "oaep",
        kuru_calistirma: bool = False,
        yedek_al: bool = True,
        hedef_cikti_dizini: Optional[str] = None
    ) -> None:
        # rsa çözücü yapılandırmasını tanımlar.
        super().__init__(
            kuru_calistirma=kuru_calistirma,
            yedek_al=yedek_al,
            hedef_cikti_dizini=hedef_cikti_dizini
        )
        self.ozel_anahtar_pem: bytes = ozel_anahtar_pem
        self.dolgu_turu: str = dolgu_turu.lower()

        # pem verisinden özel anahtarı yükler.
        self.ozel_anahtar = serialization.load_pem_private_key(
            self.ozel_anahtar_pem,
            password=parola,
            backend=default_backend()
        )

    def baytlari_coz(self, sifreli_baytlar: bytes) -> bytes:
        # rsa özel anahtarıyla şifreli blokları çözer.
        if self.dolgu_turu == "oaep":
            dolgu_nesnesi = padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        else:
            dolgu_nesnesi = padding.PKCS1v15()

        # veri tek blok ise doğrudan çözer.
        anahtar_boyutu_bayt = self.ozel_anahtar.key_size // 8

        if len(sifreli_baytlar) <= anahtar_boyutu_bayt:
            return self.ozel_anahtar.decrypt(sifreli_baytlar, dolgu_nesnesi)

        # dosya çoklu blok ise blok blok çözer.
        cozulen_parcalar = bytearray()
        for ofset in range(0, len(sifreli_baytlar), anahtar_boyutu_bayt):
            blok = sifreli_baytlar[ofset:ofset + anahtar_boyutu_bayt]
            if len(blok) == anahtar_boyutu_bayt:
                cozulen_blok = self.ozel_anahtar.decrypt(blok, dolgu_nesnesi)
                cozulen_parcalar.extend(cozulen_blok)

        return bytes(cozulen_parcalar)
