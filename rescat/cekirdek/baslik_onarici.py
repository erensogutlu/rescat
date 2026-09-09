import os
import shutil
from typing import Dict, Optional

# yaygın dosya formatlarının sağlam başlık kalıpları.
STANDART_BASLIK_SABLONLARI: Dict[str, bytes] = {
    "sqlite": b"SQLite format 3\x00\x10\x00\x01\x01\x00@  \x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
    "png": b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR",
    "pdf": b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n",
    "zip": b"PK\x03\x04\x14\x00\x00\x00\x08\x00",
    "docx": b"PK\x03\x04\x14\x00\x06\x00\x08\x00",
    "xlsx": b"PK\x03\x04\x14\x00\x06\x00\x08\x00",
    "jpg": b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00",
    "jpeg": b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00",
    "mp4": b"\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00isommp42"
}


def baslik_yama(
    hasarli_dosya_yolu: str,
    hedef_format: Optional[str] = None,
    cikti_dosya_yolu: Optional[str] = None,
    ezilen_bayt_boyutu: Optional[int] = None,
    format_anahtari: Optional[str] = None
) -> Dict[str, any]:
    # hasarlı dosya başlığını şablonla onarır.
    if not os.path.exists(hasarli_dosya_yolu):
        return {"basarili": False, "hata": "dosya bulunamadi"}

    secilen_format = hedef_format or format_anahtari
    if not secilen_format:
        return {"basarili": False, "hata": "hedef format belirtilmedi"}

    format_anahtari_temiz = secilen_format.lower().lstrip(".")
    if format_anahtari_temiz not in STANDART_BASLIK_SABLONLARI:
        return {
            "basarili": False,
            "hata": f"desteklenmeyen format. desteklenenler: {', '.join(STANDART_BASLIK_SABLONLARI.keys())}"
        }

    sablon = STANDART_BASLIK_SABLONLARI[format_anahtari_temiz]
    sablon_uzunlugu = len(sablon)

    # boyut belirtilmediyse şablon boyutunu referans alır.
    kesme_ofseti = ezilen_bayt_boyutu if ezilen_bayt_boyutu is not None else sablon_uzunlugu

    try:
        with open(hasarli_dosya_yolu, "rb") as dosya_nesnesi:
            dosya_nesnesi.seek(kesme_ofseti)
            kalan_saglam_govde = dosya_nesnesi.read()

        onarilyan_veri = sablon + kalan_saglam_govde

        hedef_yol = cikti_dosya_yolu or (hasarli_dosya_yolu + ".onarildi")
        with open(hedef_yol, "wb") as cikti_nesnesi:
            cikti_nesnesi.write(onarilyan_veri)

        return {
            "basarili": True,
            "orijinal_dosya": hasarli_dosya_yolu,
            "onarilan_dosya": hedef_yol,
            "format": format_anahtari_temiz,
            "eklenen_baslik_boyutu": sablon_uzunlugu,
            "kurtarilan_govde_boyutu": len(kalan_saglam_govde)
        }
    except Exception as hata_mesaji:
        return {"basarili": False, "hata": str(hata_mesaji)}
