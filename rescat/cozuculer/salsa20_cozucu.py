import struct
from typing import Optional
from rescat.cozuculer.temel_cozucu import TemelCozucu


def _sola_dondur32(v: int, c: int) -> int:
    return ((v << c) & 0xFFFFFFFF) | (v >> (32 - c))


def _salsa20_ceyrek_tur(y: list, a: int, b: int, c: int, d: int) -> None:
    y[b] ^= _sola_dondur32((y[a] + y[d]) & 0xFFFFFFFF, 7)
    y[c] ^= _sola_dondur32((y[b] + y[a]) & 0xFFFFFFFF, 9)
    y[d] ^= _sola_dondur32((y[c] + y[b]) & 0xFFFFFFFF, 13)
    y[a] ^= _sola_dondur32((y[d] + y[c]) & 0xFFFFFFFF, 18)


def _salsa20_blok(anahtar: bytes, nonce: bytes, sayac: int, dongu_sayisi: int = 20) -> bytes:
    # 16 veya 32 bayt anahtar ve 8 bayt nonce.
    if len(anahtar) == 32:
        sabitler = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]  # 32 baytlık sabit.
        k = list(struct.unpack("<8I", anahtar))
        k0, k1 = k[:4], k[4:]
    elif len(anahtar) == 16:
        sabitler = [0x61707865, 0x3120646e, 0x79622d36, 0x6b206574]  # 16 baytlık sabit.
        k = list(struct.unpack("<4I", anahtar))
        k0, k1 = k, k
    else:
        raise ValueError("Salsa20 anahtar boyutu 16 veya 32 bayt olmalidir.")

    n = list(struct.unpack("<2I", nonce[:8]))
    s0 = sayac & 0xFFFFFFFF
    s1 = (sayac >> 32) & 0xFFFFFFFF

    # 16 kelimelik başlangıç matrisi.
    x = [
        sabitler[0], k0[0], k0[1], k0[2],
        k0[3], sabitler[1], n[0], n[1],
        s0, s1, sabitler[2], k1[0],
        k1[1], k1[2], k1[3], sabitler[3]
    ]
    y = list(x)

    for _ in range(0, dongu_sayisi, 2):
        # sütun turu işlemi.
        _salsa20_ceyrek_tur(y, 0, 4, 8, 12)
        _salsa20_ceyrek_tur(y, 5, 9, 13, 1)
        _salsa20_ceyrek_tur(y, 10, 14, 2, 6)
        _salsa20_ceyrek_tur(y, 15, 3, 7, 11)
        # satır turu işlemi.
        _salsa20_ceyrek_tur(y, 0, 1, 2, 3)
        _salsa20_ceyrek_tur(y, 5, 6, 7, 4)
        _salsa20_ceyrek_tur(y, 10, 11, 8, 9)
        _salsa20_ceyrek_tur(y, 15, 12, 13, 14)

    cikis = [(y[i] + x[i]) & 0xFFFFFFFF for i in range(16)]
    return struct.pack("<16I", *cikis)


class Salsa20Cozucu(TemelCozucu):
    # salsa20 akış şifre çözücü sınıfı.
    def __init__(
        self,
        anahtar_baytlari: bytes,
        nonce: Optional[bytes] = None,
        nonce_dosya_basinda_mi: bool = True,
        dongu_sayisi: int = 20,
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
        self.nonce: Optional[bytes] = nonce
        self.nonce_dosya_basinda_mi: bool = nonce_dosya_basinda_mi
        self.dongu_sayisi: int = dongu_sayisi

    def baytlari_coz(self, sifreli_baytlar: bytes) -> bytes:
        if not sifreli_baytlar:
            return b""

        kullanilacak_nonce = self.nonce
        veri = sifreli_baytlar

        if kullanilacak_nonce is None:
            if self.nonce_dosya_basinda_mi and len(veri) >= 8:
                kullanilacak_nonce = veri[:8]
                veri = veri[8:]
            else:
                kullanilacak_nonce = b"\x00" * 8

        cozulmus = bytearray(len(veri))
        sayac = 0
        ofset = 0
        toplam = len(veri)

        while ofset < toplam:
            blok = _salsa20_blok(self.anahtar_baytlari, kullanilacak_nonce, sayac, self.dongu_sayisi)
            kalan = min(64, toplam - ofset)
            for i in range(kalan):
                cozulmus[ofset + i] = veri[ofset + i] ^ blok[i]
            ofset += kalan
            sayac += 1

        return bytes(cozulmus)


def salsa20_sifrele_coz(anahtar: bytes, nonce: bytes, veri: bytes, rounds: int = 20) -> bytes:
    # salsa20 şifre çözme yardımcısı.
    cozucu = Salsa20Cozucu(
        anahtar_baytlari=anahtar,
        nonce=nonce,
        nonce_dosya_basinda_mi=False,
        dongu_sayisi=rounds
    )
    return cozucu.baytlari_coz(veri)
