import os
from typing import Dict, List, Optional, Tuple, Any
from rescat.cekirdek.dosya_tanimlayici import BILINEN_SIHIRLI_BAYTLAR, format_icerik_dogrula


class OtomatikCribDragMotoru:
    """
    akis sifreleyicilerde (chacha20, salsa20, aes-ctr, rc4) olusan
    nonce/ıv reuse zafiyetini istismar ederek sifreli dosyalari
    anahtarsiz (keyless) olarak cozen otomatik crib-dragging motoru.
    c1 ^ c2 = p1 ^ p2
    """
    STANDART_CRIBLER = [
        b"%PDF-1.7\n", b"%PDF-1.4\n", b"%PDF-1.5\n", b"%PDF-1.6\n", b"%PDF-1.3\n",
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR", b"PK\x03\x04\x14\x00\x00\x00",
        b"SQLite format 3\x00", b"{\n  \"version\":", b"<?xml version=\"1.0\"",
        b"<!DOCTYPE html>\n", b"GIF89a\x00\x00", b"\xff\xd8\xff\xe0\x00\x10JFIF",
        b"The Project Gutenberg", b"Content-Type: text/plain", b"SELECT * FROM "
    ]

    @staticmethod
    def xor_baytlari(b1: bytes, b2: bytes) -> bytes:
        """ıki bayt dizisini xor'lar (en kisa olana gore)"""
        uzunluk = min(len(b1), len(b2))
        return bytes(b1[i] ^ b2[i] for i in range(uzunluk))

    @classmethod
    def ortak_keystream_turet(
        cls,
        sifreli1: bytes,
        sifreli2: bytes,
        bilinen_p1: Optional[bytes] = None
    ) -> Optional[bytes]:
        """
        eger p1 biliniyorsa veya tahmin edilebiliyorsa:
        keystream = c1 ^ p1
        p2 = c2 ^ keystream
        """
        if bilinen_p1:
            keystream = cls.xor_baytlari(sifreli1[:len(bilinen_p1)], bilinen_p1)
            return keystream

        # bilinen başlık adayları üzerinden dener.
        xor_fark = cls.xor_baytlari(sifreli1, sifreli2)

        for crib in cls.STANDART_CRIBLER:
            if len(crib) > len(xor_fark):
                continue
            
            # durum a: bilinen metin ilk dosyada mı kontrolü.
            tahmin_p2 = cls.xor_baytlari(xor_fark[:len(crib)], crib)
            gecerli2, tur2 = format_icerik_dogrula(tahmin_p2)
            if gecerli2 and tur2:
                # dosya 1 metin, dosya 2 tahmin eşlemesi.
                keystream = cls.xor_baytlari(sifreli1[:len(crib)], crib)
                return keystream

            # durum b: bilinen metin ikinci dosyada mı kontrolü.
            tahmin_p1 = cls.xor_baytlari(xor_fark[:len(crib)], crib)
            gecerli1, tur1 = format_icerik_dogrula(tahmin_p1)
            if gecerli1 and tur1:
                # dosya 1 tahmin, dosya 2 metin eşlemesi.
                keystream = cls.xor_baytlari(sifreli2[:len(crib)], crib)
                return keystream

        return None

    @classmethod
    def dosyadan_anahtarsiz_coz(
        cls,
        dosya1_yolu: str,
        dosya2_yolu: str,
        bilinen_dosya1_baslik: Optional[bytes] = None
    ) -> Dict[str, Any]:
        """
        ayni anahtar ve nonce ile sifrelenmis iki dosyayi anahtarsiz olarak deşifre eder.
        """
        try:
            with open(dosya1_yolu, "rb") as f1, open(dosya2_yolu, "rb") as f2:
                c1 = f1.read()
                c2 = f2.read()

            keystream = cls.ortak_keystream_turet(c1, c2, bilinen_dosya1_baslik)
            if not keystream:
                return {
                    "basarili": False,
                    "hata": "Ortak dosya basligi veya bilinen metin eslesmedi."
                }

            # anahtar akışıyla iki dosyanın da çözümünü üretir.
            p1_parca = cls.xor_baytlari(c1, keystream)
            p2_parca = cls.xor_baytlari(c2, keystream)

            _, tur1 = format_icerik_dogrula(p1_parca)
            _, tur2 = format_icerik_dogrula(p2_parca)

            return {
                "basarili": True,
                "keystream_boyutu": len(keystream),
                "dosya1_tur": tur1,
                "dosya2_tur": tur2,
                "dosya1_cozulmus_on_bayt": p1_parca[:32].hex(),
                "dosya2_cozulmus_on_bayt": p2_parca[:32].hex()
            }
        except Exception as e:
            return {"basarili": False, "hata": str(e)}
