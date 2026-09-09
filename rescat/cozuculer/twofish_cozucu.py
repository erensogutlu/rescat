import struct
from typing import Optional, List
from rescat.cozuculer.temel_cozucu import TemelCozucu

# twofish sabitleri ve permütasyonları.
_Q0 = [
    0xA9, 0x67, 0xB3, 0xE8, 0x04, 0xFD, 0xA3, 0x76, 0x9A, 0x92, 0x80, 0x78,
    0xE4, 0xDD, 0xD1, 0x38, 0x0D, 0xC6, 0x35, 0x98, 0x18, 0xF7, 0xEC, 0x6C,
    0x43, 0x75, 0x37, 0x26, 0xFA, 0x13, 0x94, 0x48, 0xF2, 0xD0, 0x8B, 0x30,
    0x84, 0x54, 0xDF, 0x23, 0x19, 0x5B, 0x3D, 0x59, 0xF3, 0xAE, 0xA2, 0x82,
    0x63, 0x01, 0x83, 0x2E, 0xD9, 0x51, 0x9B, 0x7C, 0xA6, 0xEB, 0xA5, 0xBE,
    0x16, 0x0C, 0xE3, 0x61, 0xC0, 0x8C, 0x3A, 0xF5, 0x73, 0x2C, 0x25, 0x0B,
    0xBB, 0x4E, 0x89, 0x6B, 0x53, 0x6A, 0xB4, 0xF1, 0xE1, 0xE6, 0xBD, 0x45,
    0xE2, 0xF4, 0xB6, 0x66, 0xCC, 0x95, 0x03, 0x56, 0xD4, 0x1C, 0x1E, 0xD7,
    0xFB, 0xC3, 0x8E, 0xB5, 0xE9, 0xCF, 0xBF, 0xBA, 0xEA, 0x77, 0x39, 0xAF,
    0x33, 0xC9, 0x62, 0x71, 0x81, 0x79, 0x09, 0xAD, 0x24, 0xCD, 0xF9, 0xD8,
    0xE5, 0xC5, 0xB9, 0x4D, 0x44, 0x08, 0x86, 0xE7, 0xA1, 0x1D, 0xAA, 0xED,
    0x06, 0x70, 0xB2, 0xD2, 0x41, 0x7B, 0xA0, 0x11, 0x31, 0xC2, 0x27, 0x90,
    0x20, 0xF6, 0x60, 0xFF, 0x96, 0x5C, 0xB1, 0xAB, 0x9E, 0x9C, 0x52, 0x1B,
    0x5F, 0x93, 0x0A, 0xEF, 0x91, 0x85, 0x49, 0xEE, 0x2D, 0x4F, 0x8F, 0x3B,
    0x47, 0x87, 0x6D, 0x46, 0xD6, 0x3E, 0x69, 0x64, 0x2A, 0xCE, 0xCB, 0x2F,
    0xFC, 0x97, 0x05, 0x7A, 0xAC, 0x7F, 0xD5, 0x1A, 0x4B, 0x0E, 0xA7, 0x5A,
    0x28, 0x14, 0x3F, 0x29, 0x88, 0x3C, 0x4C, 0x02, 0xB8, 0xDA, 0xB0, 0x17,
    0x55, 0x1F, 0x8A, 0x7D, 0x57, 0xC7, 0x8D, 0x74, 0xB7, 0xC4, 0x9F, 0x72,
    0x7E, 0x15, 0x22, 0x12, 0x58, 0x07, 0x99, 0x34, 0x6E, 0x50, 0xDE, 0x68,
    0x65, 0xBC, 0xDB, 0xF8, 0xC8, 0xA8, 0x2B, 0x40, 0xDC, 0xFE, 0x32, 0xA4,
    0xCA, 0x10, 0x21, 0xF0, 0xD3, 0x5D, 0x0F, 0x00, 0x6F, 0x9D, 0x36, 0x42,
    0x4A, 0x5E, 0xC1, 0xE0
]

_Q1 = [
    0x75, 0xF3, 0xC6, 0xF4, 0xDB, 0x7B, 0xFB, 0xC8, 0x4A, 0xD3, 0xE6, 0x6B,
    0x45, 0x7D, 0xE8, 0x4B, 0xD6, 0x32, 0xD8, 0xFD, 0x37, 0x71, 0xF1, 0xE1,
    0x30, 0x0F, 0xF8, 0x1B, 0x87, 0xFA, 0x06, 0x3F, 0x5E, 0xBA, 0xAE, 0x5B,
    0x8A, 0x00, 0xBC, 0x9D, 0x6D, 0xC1, 0xB1, 0x0E, 0x80, 0x5D, 0xD2, 0xD5,
    0xA0, 0x84, 0x07, 0x14, 0xB5, 0x90, 0x2C, 0xA3, 0xB2, 0x73, 0x4C, 0x54,
    0x92, 0x74, 0x36, 0x51, 0x38, 0xB0, 0xBD, 0x5A, 0xFC, 0x60, 0x62, 0x96,
    0x6C, 0x42, 0xF7, 0x10, 0x7C, 0x28, 0x27, 0x8C, 0x13, 0x95, 0x9C, 0xC7,
    0x24, 0x46, 0x3B, 0x70, 0xCA, 0xE3, 0x85, 0xCB, 0x11, 0xD0, 0x93, 0xB8,
    0xA6, 0x83, 0x20, 0xFF, 0x9F, 0x77, 0xC3, 0xCC, 0x03, 0x6F, 0x08, 0xBF,
    0x40, 0xE7, 0x2B, 0xE2, 0x79, 0x0C, 0xAA, 0x82, 0x41, 0x3A, 0xEA, 0xB9,
    0xE4, 0x9A, 0xA4, 0x97, 0x7E, 0xDA, 0x7A, 0x17, 0x66, 0x94, 0xA1, 0x1D,
    0x3D, 0xF0, 0xDE, 0xB3, 0x0B, 0x72, 0xA7, 0x1C, 0xEF, 0xD1, 0x53, 0x3E,
    0x8F, 0x33, 0x26, 0x5F, 0xEC, 0x76, 0x2A, 0x49, 0x81, 0x88, 0xEE, 0x21,
    0xC4, 0x1A, 0xEB, 0xD9, 0xC5, 0x39, 0x99, 0xCD, 0xAD, 0x31, 0x8B, 0x01,
    0x18, 0x23, 0xDD, 0x1F, 0x4E, 0x2D, 0xF9, 0x48, 0x4F, 0xF2, 0x65, 0x8E,
    0x78, 0x5C, 0x58, 0x19, 0x8D, 0xE5, 0x98, 0x57, 0x67, 0x7F, 0x05, 0x64,
    0xAF, 0x63, 0xB6, 0xFE, 0xF5, 0xB7, 0x3C, 0xA5, 0xCE, 0xE9, 0x68, 0x44,
    0xE0, 0x4D, 0x43, 0x69, 0x29, 0x2E, 0xAC, 0x15, 0x59, 0xA8, 0x0A, 0x9E,
    0x6E, 0x47, 0xDF, 0x34, 0x35, 0x6A, 0xCF, 0xDC, 0x22, 0xC9, 0xC0, 0x9B,
    0x89, 0xD4, 0xED, 0xAB, 0x12, 0xA2, 0x0D, 0x52, 0xBB, 0x02, 0x2F, 0xA9,
    0xD7, 0x61, 0x1E, 0xB4, 0x50, 0x04, 0xF6, 0xC2, 0x16, 0x25, 0x86, 0x56,
    0x55, 0x09, 0xBE, 0x91
]


def _gf_mult(a: int, b: int, mod: int = 0x169) -> int:
    # galois alanı gf(2^8) çarpımı.
    res = 0
    for _ in range(8):
        if b & 1:
            res ^= a
        high = a & 0x80
        a = (a << 1) & 0xFF
        if high:
            a ^= (mod & 0xFF)
        b >>= 1
    return res


def _mds_mult(x0: int, x1: int, x2: int, x3: int) -> int:
    # twofish mds matris çarpımı.
    # [01 ef 5b 5b]
    # [5b ef ec 14]
    # [ec 5b ef 1a]
    # [1a ef 5b ec]
    y0 = x0 ^ _gf_mult(0xEF, x1) ^ _gf_mult(0x5B, x2) ^ _gf_mult(0x5B, x3)
    y1 = _gf_mult(0x5B, x0) ^ _gf_mult(0xEF, x1) ^ _gf_mult(0xEC, x2) ^ _gf_mult(0x14, x3)
    y2 = _gf_mult(0xEC, x0) ^ _gf_mult(0x5B, x1) ^ _gf_mult(0xEF, x2) ^ _gf_mult(0x1A, x3)
    y3 = _gf_mult(0x1A, x0) ^ _gf_mult(0xEF, x1) ^ _gf_mult(0x5B, x2) ^ _gf_mult(0xEC, x3)
    return y0 | (y1 << 8) | (y2 << 16) | (y3 << 24)


def _rs_mult(row: list, b: list) -> int:
    res = 0
    for r, val in zip(row, b):
        res ^= _gf_mult(r, val, 0x14D)
    return res


class TwofishEngine:
    # saf python twofish motoru.
    def __init__(self, key: bytes) -> None:
        key_len = len(key)
        if key_len not in (16, 24, 32):
            if key_len < 16:
                key = key.ljust(16, b"\x00")
            elif key_len < 24:
                key = key.ljust(24, b"\x00")
            elif key_len < 32:
                key = key.ljust(32, b"\x00")
            else:
                key = key[:32]
        self.k_len = len(key)
        self.k = self.k_len // 8  # anahtar uzunluk çarpanı.

        # anahtarı 32-bit kelimelere ayırır.
        words = list(struct.unpack(f"<{len(key)//4}I", key))
        m_even = words[0::2]
        m_odd = words[1::2]

        # reed-solomon kodu ile s-kutusu vektörü oluşturur.
        rs_matrix = [
            [0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E],
            [0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5],
            [0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19],
            [0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03]
        ]
        s_box_keys = []
        for i in range(self.k - 1, -1, -1):
            b_bytes = list(key[i * 8:(i + 1) * 8])
            s_word = 0
            for row_idx in range(4):
                s_byte = _rs_mult(rs_matrix[row_idx], b_bytes)
                s_word |= (s_byte << (row_idx * 8))
            s_box_keys.append(s_word)
        self.s_box_keys = s_box_keys

        # alt anahtarları oluşturur.
        self.subkeys = []
        rho = 0x01010101
        for i in range(20):
            a = self._h(2 * i * rho, m_even)
            b = self._rol32(self._h((2 * i + 1) * rho, m_odd), 8)
            k_2i = (a + b) & 0xFFFFFFFF
            k_2i1 = self._rol32((a + 2 * b) & 0xFFFFFFFF, 9)
            self.subkeys.append(k_2i)
            self.subkeys.append(k_2i1)

    @staticmethod
    def _rol32(v: int, c: int) -> int:
        return ((v << c) & 0xFFFFFFFF) | (v >> (32 - c))

    @staticmethod
    def _ror32(v: int, c: int) -> int:
        return (v >> c) | ((v << (32 - c)) & 0xFFFFFFFF)

    def _h(self, x: int, l_list: List[int]) -> int:
        b0 = x & 0xFF
        b1 = (x >> 8) & 0xFF
        b2 = (x >> 16) & 0xFF
        b3 = (x >> 24) & 0xFF

        if self.k >= 4:
            l3 = l_list[3]
            b0 = _Q1[b0] ^ (l3 & 0xFF)
            b1 = _Q0[b1] ^ ((l3 >> 8) & 0xFF)
            b2 = _Q0[b2] ^ ((l3 >> 16) & 0xFF)
            b3 = _Q1[b3] ^ ((l3 >> 24) & 0xFF)
        if self.k >= 3:
            l2 = l_list[2]
            b0 = _Q1[b0] ^ (l2 & 0xFF)
            b1 = _Q1[b1] ^ ((l2 >> 8) & 0xFF)
            b2 = _Q0[b2] ^ ((l2 >> 16) & 0xFF)
            b3 = _Q0[b3] ^ ((l2 >> 24) & 0xFF)
        if self.k >= 2:
            l1 = l_list[1]
            l0 = l_list[0]
            b0 = _Q1[_Q0[_Q0[b0] ^ (l1 & 0xFF)] ^ (l0 & 0xFF)]
            b1 = _Q0[_Q0[_Q1[b1] ^ ((l1 >> 8) & 0xFF)] ^ ((l0 >> 8) & 0xFF)]
            b2 = _Q1[_Q1[_Q0[b2] ^ ((l1 >> 16) & 0xFF)] ^ ((l0 >> 16) & 0xFF)]
            b3 = _Q0[_Q1[_Q1[b3] ^ ((l1 >> 24) & 0xFF)] ^ ((l0 >> 24) & 0xFF)]

        return _mds_mult(b0, b1, b2, b3)

    def _g(self, x: int) -> int:
        return self._h(x, self.s_box_keys)

    def blok_sifrele(self, blok: bytes) -> bytes:
        r = list(struct.unpack("<4I", blok))
        for i in range(4):
            r[i] ^= self.subkeys[i]

        for i in range(16):
            t0 = self._g(r[0])
            t1 = self._g(self._rol32(r[1], 8))
            f0 = (t0 + t1 + self.subkeys[2 * i + 8]) & 0xFFFFFFFF
            f1 = (t0 + 2 * t1 + self.subkeys[2 * i + 9]) & 0xFFFFFFFF
            r[2] = self._ror32(r[2] ^ f0, 1)
            r[3] = self._rol32(r[3], 1) ^ f1
            if i < 15:
                r[0], r[1], r[2], r[3] = r[2], r[3], r[0], r[1]

        r[2] ^= self.subkeys[4]
        r[3] ^= self.subkeys[5]
        r[0] ^= self.subkeys[6]
        r[1] ^= self.subkeys[7]
        return struct.pack("<4I", r[2], r[3], r[0], r[1])

    def blok_coz(self, blok: bytes) -> bytes:
        r = list(struct.unpack("<4I", blok))
        r[0] ^= self.subkeys[4]
        r[1] ^= self.subkeys[5]
        r[2] ^= self.subkeys[6]
        r[3] ^= self.subkeys[7]

        for i in range(15, -1, -1):
            t0 = self._g(r[2])
            t1 = self._g(self._rol32(r[3], 8))
            f0 = (t0 + t1 + self.subkeys[2 * i + 8]) & 0xFFFFFFFF
            f1 = (t0 + 2 * t1 + self.subkeys[2 * i + 9]) & 0xFFFFFFFF
            r[0] = self._rol32(r[0], 1) ^ f0
            r[1] = self._ror32(r[1] ^ f1, 1)
            if i > 0:
                r[0], r[1], r[2], r[3] = r[2], r[3], r[0], r[1]

        p0 = r[2] ^ self.subkeys[0]
        p1 = r[3] ^ self.subkeys[1]
        p2 = r[0] ^ self.subkeys[2]
        p3 = r[1] ^ self.subkeys[3]
        return struct.pack("<4I", p0, p1, p2, p3)


class TwofishCozucu(TemelCozucu):
    # twofish blok şifre çözücü sınıfı.
    def __init__(
        self,
        anahtar_baytlari: bytes,
        mod_adi: str = "cbc",
        baslatma_vektoru: Optional[bytes] = None,
        iv_dosya_basinda_mi: bool = True,
        kuru_calistirma: bool = False,
        yedek_al: bool = True,
        hedef_cikti_dizini: Optional[str] = None
    ) -> None:
        super().__init__(kuru_calistirma=kuru_calistirma, yedek_al=yedek_al, hedef_cikti_dizini=hedef_cikti_dizini)
        self.motor = TwofishEngine(anahtar_baytlari)
        self.mod_adi = mod_adi.lower()
        self.baslatma_vektoru = baslatma_vektoru
        self.iv_dosya_basinda_mi = iv_dosya_basinda_mi

    def baytlari_coz(self, sifreli_baytlar: bytes) -> bytes:
        if not sifreli_baytlar:
            return b""

        kullanilacak_iv = self.baslatma_vektoru
        veri = sifreli_baytlar

        if self.mod_adi in ("cbc", "ctr"):
            if kullanilacak_iv is None:
                if self.iv_dosya_basinda_mi and len(veri) >= 16:
                    kullanilacak_iv = veri[:16]
                    veri = veri[16:]
                else:
                    kullanilacak_iv = b"\x00" * 16

        # blok katlarına uymuyorsa fazlalıkları ayarlar.
        if self.mod_adi in ("cbc", "ecb") and len(veri) % 16 != 0:
            veri = veri[:len(veri) - (len(veri) % 16)]

        if not veri:
            return b""

        cozulmus = bytearray()

        if self.mod_adi == "cbc":
            onceki = kullanilacak_iv
            for i in range(0, len(veri), 16):
                blok = veri[i:i + 16]
                d = self.motor.blok_coz(blok)
                cozulmus.extend(bytes(a ^ b for a, b in zip(d, onceki)))
                onceki = blok
        elif self.mod_adi == "ecb":
            for i in range(0, len(veri), 16):
                blok = veri[i:i + 16]
                cozulmus.extend(self.motor.blok_coz(blok))
        elif self.mod_adi == "ctr":
            sayac = int.from_bytes(kullanilacak_iv, "big")
            for i in range(0, len(veri), 16):
                sayac_bayt = sayac.to_bytes(16, "big")
                keystream = self.motor.blok_sifrele(sayac_bayt)
                parca = veri[i:i + 16]
                cozulmus.extend(bytes(a ^ b for a, b in zip(parca, keystream[:len(parca)])))
                sayac = (sayac + 1) & ((1 << 128) - 1)
        else:
            return veri

        # pkcs7 dolgusunu kaldırır.
        if self.mod_adi in ("cbc", "ecb") and cozulmus:
            dolgu = cozulmus[-1]
            if 1 <= dolgu <= 16 and cozulmus[-dolgu:] == bytes([dolgu] * dolgu):
                return bytes(cozulmus[:-dolgu])

        return bytes(cozulmus)
