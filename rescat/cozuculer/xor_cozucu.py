from typing import Optional
from rescat.cozuculer.temel_cozucu import TemelCozucu


class XorCozucu(TemelCozucu):
    # statik ve döngüsel xor çözücü sınıfı.
    def __init__(
        self,
        anahtar_baytlari: bytes,
        kaydirmali_mi: bool = False,
        kuru_calistirma: bool = False,
        yedek_al: bool = True,
        hedef_cikti_dizini: Optional[str] = None
    ) -> None:
        # xor çözücü parametrelerini başlatır.
        super().__init__(
            kuru_calistirma=kuru_calistirma,
            yedek_al=yedek_al,
            hedef_cikti_dizini=hedef_cikti_dizini
        )
        self.anahtar_baytlari: bytes = anahtar_baytlari
        self.kaydirmali_mi: bool = kaydirmali_mi

        if not self.anahtar_baytlari:
            raise ValueError("anahtar baytlari bos olamaz")

    def baytlari_coz(self, sifreli_baytlar: bytes) -> bytes:
        # xor işlemi ile şifreyi çözer.
        anahtar_uzunlugu = len(self.anahtar_baytlari)
        cozulmus_veri = bytearray(len(sifreli_baytlar))

        if not self.kaydirmali_mi:
            # standart periyodik xor işlemi.
            for indeks, bayt in enumerate(sifreli_baytlar):
                cozulmus_veri[indeks] = bayt ^ self.anahtar_baytlari[indeks % anahtar_uzunlugu]
        else:
            # kaydırmalı xor işlemi.
            for indeks, bayt in enumerate(sifreli_baytlar):
                anahtar_degeri = (self.anahtar_baytlari[indeks % anahtar_uzunlugu] + indeks) & 0xFF
                cozulmus_veri[indeks] = bayt ^ anahtar_degeri

        return bytes(cozulmus_veri)
