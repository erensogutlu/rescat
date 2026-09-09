import struct
from typing import Optional, List, Tuple
from rescat.cozuculer.temel_cozucu import TemelCozucu

DELTA = 0x9E3779B9


def _pkcs7_unpad(veri: bytes, blok_boyutu: int = 8) -> bytes:
    if not veri:
        return veri
    dolgu_miktari = veri[-1]
    if 1 <= dolgu_miktari <= blok_boyutu:
        if veri[-dolgu_miktari:] == bytes([dolgu_miktari] * dolgu_miktari):
            return veri[:-dolgu_miktari]
    return veri


def _tea_blok_coz(v0: int, v1: int, k: List[int], dongu: int = 32) -> Tuple[int, int]:
    # standart tea blok deşifreleme.
    toplam = (DELTA * dongu) & 0xFFFFFFFF
    for _ in range(dongu):
        v1 = (v1 - (((v0 << 4) + k[2]) ^ (v0 + toplam) ^ ((v0 >> 5) + k[3]))) & 0xFFFFFFFF
        v0 = (v0 - (((v1 << 4) + k[0]) ^ (v1 + toplam) ^ ((v1 >> 5) + k[1]))) & 0xFFFFFFFF
        toplam = (toplam - DELTA) & 0xFFFFFFFF
    return v0, v1


def _tea_blok_sifrele(v0: int, v1: int, k: List[int], dongu: int = 32) -> Tuple[int, int]:
    toplam = 0
    for _ in range(dongu):
        toplam = (toplam + DELTA) & 0xFFFFFFFF
        v0 = (v0 + (((v1 << 4) + k[0]) ^ (v1 + toplam) ^ ((v1 >> 5) + k[1]))) & 0xFFFFFFFF
        v1 = (v1 + (((v0 << 4) + k[2]) ^ (v0 + toplam) ^ ((v0 >> 5) + k[3]))) & 0xFFFFFFFF
    return v0, v1


def _xtea_blok_coz(v0: int, v1: int, k: List[int], dongu: int = 32) -> Tuple[int, int]:
    # gelişmiş xtea blok deşifreleme.
    toplam = (DELTA * dongu) & 0xFFFFFFFF
    for _ in range(dongu):
        v1 = (v1 - ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (toplam + k[(toplam >> 11) & 3]))) & 0xFFFFFFFF
        toplam = (toplam - DELTA) & 0xFFFFFFFF
        v0 = (v0 - ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (toplam + k[toplam & 3]))) & 0xFFFFFFFF
    return v0, v1


def _xtea_blok_sifrele(v0: int, v1: int, k: List[int], dongu: int = 32) -> Tuple[int, int]:
    toplam = 0
    for _ in range(dongu):
        v0 = (v0 + ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (toplam + k[toplam & 3]))) & 0xFFFFFFFF
        toplam = (toplam + DELTA) & 0xFFFFFFFF
        v1 = (v1 + ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (toplam + k[(toplam >> 11) & 3]))) & 0xFFFFFFFF
    return v0, v1


def _xxtea_dizi_coz(v: List[int], k: List[int]) -> List[int]:
    n = len(v)
    if n < 2:
        return v
    rounds = 6 + 52 // n
    toplam = (rounds * DELTA) & 0xFFFFFFFF
    y = v[0]
    while toplam != 0:
        e = (toplam >> 2) & 3
        for p in range(n - 1, -1, -1):
            z = v[p - 1] if p > 0 else v[n - 1]
            mx = (((z >> 5 ^ (y << 2) & 0xFFFFFFFF) + ((y >> 3 ^ (z << 4) & 0xFFFFFFFF))) ^
                  ((toplam ^ y) + (k[(p & 3) ^ e] ^ z))) & 0xFFFFFFFF
            v[p] = (v[p] - mx) & 0xFFFFFFFF
            y = v[p]
        toplam = (toplam - DELTA) & 0xFFFFFFFF
    return v


class TeaCozucu(TemelCozucu):
    # tea blok çözücü.
    def __init__(
        self,
        anahtar_baytlari: bytes,
        mod_adi: str = "cbc",
        baslatma_vektoru: Optional[bytes] = None,
        kuru_calistirma: bool = False,
        yedek_al: bool = True,
        hedef_cikti_dizini: Optional[str] = None
    ) -> None:
        super().__init__(kuru_calistirma=kuru_calistirma, yedek_al=yedek_al, hedef_cikti_dizini=hedef_cikti_dizini)
        if len(anahtar_baytlari) < 16:
            self.anahtar_baytlari = anahtar_baytlari.ljust(16, b"\x00")
        else:
            self.anahtar_baytlari = anahtar_baytlari[:16]
        self.k = list(struct.unpack(">4I", self.anahtar_baytlari))
        self.mod_adi = mod_adi.lower()
        self.baslatma_vektoru = baslatma_vektoru or b"\x00" * 8

    def baytlari_coz(self, sifreli_baytlar: bytes) -> bytes:
        if len(sifreli_baytlar) % 8 != 0:
            # blok boyutu uyumsuzluğunda son bloğu ayarlar.
            sifreli_baytlar = sifreli_baytlar[:len(sifreli_baytlar) - (len(sifreli_baytlar) % 8)]
        if not sifreli_baytlar:
            return b""

        cozulmus = bytearray()
        onceki_iv = self.baslatma_vektoru

        for i in range(0, len(sifreli_baytlar), 8):
            blok = sifreli_baytlar[i:i + 8]
            v0, v1 = struct.unpack(">2I", blok)
            c0, c1 = _tea_blok_coz(v0, v1, self.k)
            coz_blok = struct.pack(">2I", c0, c1)

            if self.mod_adi == "cbc":
                coz_blok = bytes(b ^ iv for b, iv in zip(coz_blok, onceki_iv))
                onceki_iv = blok

            cozulmus.extend(coz_blok)

        return _pkcs7_unpad(bytes(cozulmus), 8)


class XteaCozucu(TemelCozucu):
    # xtea blok çözücü.
    def __init__(
        self,
        anahtar_baytlari: bytes,
        mod_adi: str = "cbc",
        baslatma_vektoru: Optional[bytes] = None,
        kuru_calistirma: bool = False,
        yedek_al: bool = True,
        hedef_cikti_dizini: Optional[str] = None
    ) -> None:
        super().__init__(kuru_calistirma=kuru_calistirma, yedek_al=yedek_al, hedef_cikti_dizini=hedef_cikti_dizini)
        if len(anahtar_baytlari) < 16:
            self.anahtar_baytlari = anahtar_baytlari.ljust(16, b"\x00")
        else:
            self.anahtar_baytlari = anahtar_baytlari[:16]
        self.k = list(struct.unpack(">4I", self.anahtar_baytlari))
        self.mod_adi = mod_adi.lower()
        self.baslatma_vektoru = baslatma_vektoru or b"\x00" * 8

    def baytlari_coz(self, sifreli_baytlar: bytes) -> bytes:
        if len(sifreli_baytlar) % 8 != 0:
            sifreli_baytlar = sifreli_baytlar[:len(sifreli_baytlar) - (len(sifreli_baytlar) % 8)]
        if not sifreli_baytlar:
            return b""

        cozulmus = bytearray()
        onceki_iv = self.baslatma_vektoru

        for i in range(0, len(sifreli_baytlar), 8):
            blok = sifreli_baytlar[i:i + 8]
            v0, v1 = struct.unpack(">2I", blok)
            c0, c1 = _xtea_blok_coz(v0, v1, self.k)
            coz_blok = struct.pack(">2I", c0, c1)

            if self.mod_adi == "cbc":
                coz_blok = bytes(b ^ iv for b, iv in zip(coz_blok, onceki_iv))
                onceki_iv = blok

            cozulmus.extend(coz_blok)

        return _pkcs7_unpad(bytes(cozulmus), 8)


class XxteaCozucu(TemelCozucu):
    # xxtea blok çözücü.
    def __init__(
        self,
        anahtar_baytlari: bytes,
        kuru_calistirma: bool = False,
        yedek_al: bool = True,
        hedef_cikti_dizini: Optional[str] = None
    ) -> None:
        super().__init__(kuru_calistirma=kuru_calistirma, yedek_al=yedek_al, hedef_cikti_dizini=hedef_cikti_dizini)
        if len(anahtar_baytlari) < 16:
            self.anahtar_baytlari = anahtar_baytlari.ljust(16, b"\x00")
        else:
            self.anahtar_baytlari = anahtar_baytlari[:16]
        self.k = list(struct.unpack("<4I", self.anahtar_baytlari))

    def baytlari_coz(self, sifreli_baytlar: bytes) -> bytes:
        uzunluk = len(sifreli_baytlar)
        if uzunluk < 8:
            return sifreli_baytlar
        kalan = uzunluk % 4
        if kalan != 0:
            sifreli_baytlar = sifreli_baytlar + (b"\x00" * (4 - kalan))

        kelime_sayisi = len(sifreli_baytlar) // 4
        v = list(struct.unpack(f"<{kelime_sayisi}I", sifreli_baytlar))
        cozulmus_kelimeler = _xxtea_dizi_coz(v, self.k)
        cozulmus_bayt = struct.pack(f"<{kelime_sayisi}I", *cozulmus_kelimeler)
        return _pkcs7_unpad(cozulmus_bayt[:uzunluk], 8)
