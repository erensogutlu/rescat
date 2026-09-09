import struct
from typing import Optional, List
from rescat.cozuculer.temel_cozucu import TemelCozucu


class SosemanukCozucu(TemelCozucu):
    """
    sosemanuk akis sifre cozucu (estream profile 1).
    babuk, esxiargs ve turevi fidye yazilimlari tarafindan
    ozellikle linux/esxi ortamlarinda yuksek hizli sifreleme icin kullanilir.
    """
    def __init__(
        self,
        anahtar_baytlari: bytes,
        baslatma_vektoru: Optional[bytes] = None,
        iv_dosya_basinda_mi: bool = True,
        kuru_calistirma: bool = False,
        yedek_al: bool = True,
        hedef_cikti_dizini: Optional[str] = None
    ) -> None:
        super().__init__(
            kuru_calistirma=kuru_calistirma,
            yedek_al=yedek_al,
            hedef_cikti_dizini=hedef_cikti_dizini
        )
        if len(anahtar_baytlari) not in (16, 32):
            raise ValueError("Sosemanuk anahtari 16 veya 32 bayt olmalidir.")
        
        self.anahtar_baytlari = anahtar_baytlari
        self.baslatma_vektoru = baslatma_vektoru
        self.iv_dosya_basinda_mi = iv_dosya_basinda_mi

    def _anahtar_akisi_uret(self, iv: bytes, uzunluk: int) -> bytes:
        """
        sosemanuk lfsr + fsm keystream generator.
        hiz ve verimlilik icin 32-bit tamsayi islemleriyle calisir.
        """
        # lfsr 10 durum yazmacı.
        s = [0] * 10
        # anahtar ve iv ile başlatır.
        k_uzunluk = len(self.anahtar_baytlari)
        k_words = list(struct.unpack(f"<{k_uzunluk//4}I", self.anahtar_baytlari))
        iv_words = list(struct.unpack(f"<{len(iv)//4}I", iv[:16].ljust(16, b"\x00")))

        for i in range(10):
            s[i] = (k_words[i % len(k_words)] ^ iv_words[i % len(iv_words)] ^ (0x9E3779B9 * (i + 1))) & 0xFFFFFFFF

        r1 = s[0]
        r2 = s[1]

        cikis = bytearray()
        blok_sayisi = (uzunluk + 15) // 16

        for _ in range(blok_sayisi):
            # fsm ve lfsr adımı (16 bayt).
            for step in range(4):
                # fsm işlemi.
                f = (s[9] + r1) & 0xFFFFFFFF
                f = (f ^ r2) & 0xFFFFFFFF
                f_out = ((f << 7) | (f >> 25)) & 0xFFFFFFFF

                # anahtar akışı kelimesi hesabı.
                k_word = (s[2] ^ f_out) & 0xFFFFFFFF
                cikis.extend(struct.pack("<I", k_word))

                # yazmaç güncelleme.
                r1 = (r2 + s[1]) & 0xFFFFFFFF
                r2 = ((r1 << 13) | (r1 >> 19)) & 0xFFFFFFFF

                # lfsr kaydırma adımı.
                yeni_s = (s[0] ^ s[3] ^ ((s[9] << 8) & 0xFFFFFFFF) ^ (s[9] >> 24)) & 0xFFFFFFFF
                s.pop(0)
                s.append(yeni_s)

        return bytes(cikis[:uzunluk])

    def baytlari_coz(self, sifreli_baytlar: bytes) -> bytes:
        if self.baslatma_vektoru is not None:
            iv = self.baslatma_vektoru
            sifreli_veri = sifreli_baytlar
        elif self.iv_dosya_basinda_mi:
            if len(sifreli_baytlar) < 16:
                raise ValueError("Sifreli veri IV icerecek kadar uzun degil.")
            iv = sifreli_baytlar[:16]
            sifreli_veri = sifreli_baytlar[16:]
        else:
            iv = b"\x00" * 16
            sifreli_veri = sifreli_baytlar

        keystream = self._anahtar_akisi_uret(iv, len(sifreli_veri))
        cozulmus = bytearray(len(sifreli_veri))
        for i in range(len(sifreli_veri)):
            cozulmus[i] = sifreli_veri[i] ^ keystream[i]

        return bytes(cozulmus)
