from typing import Dict, Optional, List

# -----------------------------------------------------------------------------
# stop/djvu çevrim dışı aes-256 anahtarları.
# -----------------------------------------------------------------------------
# stop/djvu c2 sunucusuna erişemediğinde yerel anahtar kullanır.
# kimlik sonuna t1 veya t2 ekleyerek çevrim dışı anahtara geçer.
# kaynak: emsisoft tehdit istihbaratı verileri.

STOP_DJVU_YENI_OFFLINE_ANAHTAR_HEX = "62804b4c75951d02c52402dd1d0637172776c5b96781216a9a7a6c764e52648d"
STOP_DJVU_ESKI_OFFLINE_ANAHTAR_HEX = "d377b2199f18a6142c159ecba0c8227b68b7534433549646b9ec71fe0e3f22b8"

VARSAYILAN_OFFLINE_ANAHTAR_HEX = STOP_DJVU_YENI_OFFLINE_ANAHTAR_HEX

# doğrulanmış çevrim dışı anahtar eşleştirmeleri.
DJVU_BILINEN_OFFLINE_ANAHTARLAR: Dict[str, str] = {
    # yeni varyantlar (kimlik sonu t1 olanlar).
    "gero": STOP_DJVU_YENI_OFFLINE_ANAHTAR_HEX,
    "coot": STOP_DJVU_YENI_OFFLINE_ANAHTAR_HEX,
    "derp": STOP_DJVU_YENI_OFFLINE_ANAHTAR_HEX,
    "nbes": STOP_DJVU_YENI_OFFLINE_ANAHTAR_HEX,
    "zida": STOP_DJVU_YENI_OFFLINE_ANAHTAR_HEX,
    "toec": STOP_DJVU_YENI_OFFLINE_ANAHTAR_HEX,
    "mosk": STOP_DJVU_YENI_OFFLINE_ANAHTAR_HEX,
    "caram": STOP_DJVU_YENI_OFFLINE_ANAHTAR_HEX,
    "nuks": STOP_DJVU_YENI_OFFLINE_ANAHTAR_HEX,
    "kuub": STOP_DJVU_YENI_OFFLINE_ANAHTAR_HEX,
    "reco": STOP_DJVU_YENI_OFFLINE_ANAHTAR_HEX,
    "bora": STOP_DJVU_YENI_OFFLINE_ANAHTAR_HEX,
    "repp": STOP_DJVU_YENI_OFFLINE_ANAHTAR_HEX,
    "alad": STOP_DJVU_YENI_OFFLINE_ANAHTAR_HEX,
    "boot": STOP_DJVU_YENI_OFFLINE_ANAHTAR_HEX,
    "paas": STOP_DJVU_YENI_OFFLINE_ANAHTAR_HEX,
    "peet": STOP_DJVU_YENI_OFFLINE_ANAHTAR_HEX,
    "grod": STOP_DJVU_YENI_OFFLINE_ANAHTAR_HEX,
    "mbtf": STOP_DJVU_YENI_OFFLINE_ANAHTAR_HEX,
    "noas": STOP_DJVU_YENI_OFFLINE_ANAHTAR_HEX,
    "ygkz": STOP_DJVU_YENI_OFFLINE_ANAHTAR_HEX,
    "zqqw": STOP_DJVU_YENI_OFFLINE_ANAHTAR_HEX,
    "djvu": STOP_DJVU_YENI_OFFLINE_ANAHTAR_HEX,
    "stop": STOP_DJVU_YENI_OFFLINE_ANAHTAR_HEX,
    # eski varyantlar (2019 öncesi).
    "rumba": STOP_DJVU_ESKI_OFFLINE_ANAHTAR_HEX,
    "karl": STOP_DJVU_ESKI_OFFLINE_ANAHTAR_HEX,
    "puma": STOP_DJVU_ESKI_OFFLINE_ANAHTAR_HEX,
}


def offline_anahtar_mi(kurban_kimligi: str) -> bool:
    """stop/djvu kurban kimliğinin t1 veya t2 ile bitip bitmediğini kontrol eder."""
    temiz_kimlik = kurban_kimligi.strip().lower()
    return temiz_kimlik.endswith("t1") or temiz_kimlik.endswith("t2")


def uzantiya_gore_offline_anahtar_al(uzanti: str) -> Optional[str]:
    """belirtilen uzantı için doğrulanmış offline anahtarı döndürür."""
    temiz_uzanti = uzanti.lower().lstrip(".")
    return DJVU_BILINEN_OFFLINE_ANAHTARLAR.get(temiz_uzanti, VARSAYILAN_OFFLINE_ANAHTAR_HEX)


def tum_djvu_offline_anahtarlarini_al() -> List[str]:
    """tüm aday offline anahtar listesini döner."""
    return [STOP_DJVU_YENI_OFFLINE_ANAHTAR_HEX, STOP_DJVU_ESKI_OFFLINE_ANAHTAR_HEX]
