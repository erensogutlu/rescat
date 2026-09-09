import os
import io
import struct
import zlib
import gzip
import zipfile
from typing import Dict, Optional, Tuple
from rescat.cekirdek.entropi import shannon_entropisi_hesapla

# yaygın dosya formatlarının sihirli başlık baytları.
BILINEN_SIHIRLI_BAYTLAR: Dict[str, bytes] = {
    "pdf": b"%PDF-",
    "png": b"\x89PNG\r\n\x1a\n",
    "jpg": b"\xff\xd8\xff",
    "gif": b"GIF8",
    "bmp": b"BM",
    "zip": b"PK\x03\x04",
    "docx": b"PK\x03\x04",
    "xlsx": b"PK\x03\x04",
    "pptx": b"PK\x03\x04",
    "exe": b"MZ",
    "elf": b"\x7fELF",
    "tar_gz": b"\x1f\x8b",
    "sqlite": b"SQLite format 3\x00",
    "7z": b"7z\xbc\xaf\x27\x1c",
    "rar": b"Rar!\x1a\x07",
    "mp4": b"\x00\x00\x00\x18ftyp",
    "mp3": b"ID3",
    "bzip2": b"BZh",
    "xz": b"\xfd7zXZ\x00",
    "zst": b"(\xb5/\xfd",
    "flac": b"fLaC",
    "mkv": b"\x1aE\xdf\xa3",
    "ogg": b"OggS",
    "rtf": b"{\\rtf",
    "dex": b"dex\n",
    "pcap": b"\xd4\xc3\xb2\xa1",
    "pcapng": b"\n\r\r\n",
    "ps": b"%!PS",
    "vmdk": b"KDMV"
}


def sihirli_baytlardan_tur_tahmin_et(veri_baytlari: bytes) -> Optional[str]:
    # bayt dizisinin başındaki imzadan dosya türünü tespit eder.
    if not veri_baytlari or len(veri_baytlari) < 4:
        return None

    # riff taşıyıcıları (webp, wav, avi).
    if veri_baytlari.startswith(b"RIFF") and len(veri_baytlari) >= 12:
        alttur = veri_baytlari[8:12]
        if alttur == b"WEBP":
            return "webp"
        if alttur == b"WAVE":
            return "wav"
        if alttur == b"AVI ":
            return "avi"

    # matroska ve webm formatı.
    if veri_baytlari.startswith(b"\x1aE\xdf\xa3"):
        return "mkv"

    # pcap ters endian formatı.
    if veri_baytlari.startswith(b"\xa1\xb2\xc3\xd4"):
        return "pcap"

    for tur_adi, imza in BILINEN_SIHIRLI_BAYTLAR.items():
        if veri_baytlari.startswith(imza):
            return tur_adi

    return None


def format_icerik_dogrula(veri_baytlari: bytes, beklenen_tur: Optional[str] = None) -> Tuple[bool, Optional[str]]:
    """
    verilen bayt dizisinin yalnizca sihirli baytini degil,
    yapisal butunlugunu (structural integrity) ve gecerliligini dogrular.
    bozuk veya rastgele sifreli baytlarin acilmayan dosya olarak kurtarilmasini engeller.
    """
    if not veri_baytlari or len(veri_baytlari) < 4:
        return False, None

    ent = shannon_entropisi_hesapla(veri_baytlari[:4096])

    # 1. zip ve ofis arşivleri.
    if veri_baytlari.startswith(b"PK\x03\x04"):
        if ent <= 7.90:
            try:
                with zipfile.ZipFile(io.BytesIO(veri_baytlari), "r") as zf:
                    girdiler = zf.infolist()
                    if girdiler:
                        adlar = [g.filename for g in girdiler]
                        if any("word/" in a or "[Content_Types].xml" in a for a in adlar):
                            return True, "docx"
                        if any("xl/" in a for a in adlar):
                            return True, "xlsx"
                        if any("ppt/" in a for a in adlar):
                            return True, "pptx"
                        return True, "zip"
            except Exception:
                pass
            if beklenen_tur is None or beklenen_tur in ("zip", "docx", "xlsx", "pptx", "locked", "enc"):
                return True, "zip"

    # 2. gzip ve tar arşivleri.
    if veri_baytlari.startswith(b"\x1f\x8b"):
        if len(veri_baytlari) >= 10 and veri_baytlari[2] == 8 and ent <= 7.95:
            try:
                acilan = gzip.decompress(veri_baytlari[:min(len(veri_baytlari), 131072)])
                if len(acilan) > 0:
                    return True, "tar_gz"
            except Exception:
                try:
                    acilan = zlib.decompress(veri_baytlari[10:], -15)
                    if len(acilan) > 0:
                        return True, "tar_gz"
                except Exception:
                    pass

    # 3. pdf belgesi.
    if veri_baytlari.startswith(b"%PDF-"):
        if ent <= 7.95:
            return True, "pdf"

    # 4. png resmi.
    if veri_baytlari.startswith(b"\x89PNG\r\n\x1a\n"):
        if ent <= 7.95:
            return True, "png"

    # 5. jpeg resmi.
    if veri_baytlari.startswith(b"\xff\xd8\xff"):
        if (
            b"\xff\xe0" in veri_baytlari[:32]
            or b"\xff\xe1" in veri_baytlari[:32]
            or b"\xff\xdb" in veri_baytlari[:128]
            or b"\xff\xc0" in veri_baytlari[:512]
            or b"\xff\xda" in veri_baytlari
        ) and ent <= 7.95:
            return True, "jpg"

    # 6. sqlite veritabanı.
    if veri_baytlari.startswith(b"SQLite format 3\x00"):
        if len(veri_baytlari) >= 100:
            sayfa_boyutu = int.from_bytes(veri_baytlari[16:18], "big")
            if sayfa_boyutu in (512, 1024, 2048, 4096, 8192, 16384, 32768, 65536) or sayfa_boyutu == 1:
                return True, "sqlite"
        else:
            return True, "sqlite"

    # 7. 7z arşivi.
    if veri_baytlari.startswith(b"7z\xbc\xaf\x27\x1c"):
        if len(veri_baytlari) >= 32 and veri_baytlari[6] == 0:
            return True, "7z"

    # 8. rar arşivi.
    if veri_baytlari.startswith(b"Rar!\x1a\x07\x00") or veri_baytlari.startswith(b"Rar!\x1a\x07\x01\x00"):
        return True, "rar"

    # 9. mp4 video formatı.
    if len(veri_baytlari) >= 16:
        if veri_baytlari[4:8] == b"ftyp" or (veri_baytlari.startswith(b"\x00\x00\x00") and b"ftyp" in veri_baytlari[:16]):
            return True, "mp4"

    # 10. elf çalıştırılabilir ikilisi.
    if veri_baytlari.startswith(b"\x7fELF"):
        if len(veri_baytlari) >= 16 and veri_baytlari[4] in (1, 2) and veri_baytlari[5] in (1, 2):
            return True, "elf"

    # 11. pe ve exe çalıştırılabilir ikilisi.
    if veri_baytlari.startswith(b"MZ"):
        if len(veri_baytlari) >= 64:
            try:
                pe_ofset = struct.unpack("<I", veri_baytlari[0x3C:0x40])[0]
                if 0 < pe_ofset < len(veri_baytlari) - 4:
                    if veri_baytlari[pe_ofset:pe_ofset + 4] == b"PE\x00\x00":
                        return True, "exe"
            except Exception:
                pass

    # 12. düz metin, json ve xml.
    if len(veri_baytlari) >= 16 and ent <= 6.5:
        ilk_blok = veri_baytlari[:min(len(veri_baytlari), 2048)]
        basilabilir = sum(1 for b in ilk_blok if 32 <= b <= 126 or b in (9, 10, 13))
        oran = basilabilir / len(ilk_blok)
        if beklenen_tur and beklenen_tur.lower() not in (
            "txt", "csv", "json", "xml", "log", "html", "htm", "sql", "py",
            "c", "cpp", "sh", "bat", "ps1", "md", "yaml", "yml", "ini", "cfg",
            "locked", "enc", "crypto", "djvu", "ransom", ""
        ):
            return False, None

        try:
            metin = ilk_blok.decode("utf-8")
            utf8_basarili = True
        except Exception:
            utf8_basarili = False

        if utf8_basarili:
            metin_basilabilir = sum(1 for ch in metin if ch.isprintable() or ch in "\r\n\t")
            if len(metin) > 0 and (metin_basilabilir / len(metin)) >= 0.85:
                strip_b = ilk_blok.strip()
                if strip_b.startswith((b"{", b"[")):
                    try:
                        import json
                        json.loads(strip_b.decode("utf-8", errors="ignore"))
                        return True, "json"
                    except Exception:
                        pass
                if strip_b.startswith(b"<?xml") or strip_b.startswith(b"<html") or strip_b.startswith(b"<!DOCTYPE"):
                    return True, "xml"
                return True, "txt"

        if oran >= 0.85:
            return True, "txt"

    # 13. bzip2 arşivi.
    if veri_baytlari.startswith(b"BZh") and ent <= 7.95:
        return True, "bzip2"

    # 14. xz arşivi.
    if veri_baytlari.startswith(b"\xfd7zXZ\x00") and ent <= 7.95:
        return True, "xz"

    # 15. zstandard arşivi.
    if veri_baytlari.startswith(b"(\xb5/\xfd") and ent <= 7.95:
        return True, "zst"

    # 16. webp, wav ve avi (riff).
    if veri_baytlari.startswith(b"RIFF") and len(veri_baytlari) >= 12:
        tag = veri_baytlari[8:12]
        if tag == b"WEBP" and ent <= 7.95:
            return True, "webp"
        if tag == b"WAVE":
            return True, "wav"
        if tag == b"AVI ":
            return True, "avi"

    # 17. flac ses dosyası.
    if veri_baytlari.startswith(b"fLaC") and ent <= 7.95:
        return True, "flac"

    # 18. mkv ve webm videosu.
    if veri_baytlari.startswith(b"\x1aE\xdf\xa3") and ent <= 7.95:
        return True, "mkv"

    # 19. ogg ses dosyası.
    if veri_baytlari.startswith(b"OggS") and ent <= 7.95:
        return True, "ogg"

    # 20. rtf belgesi.
    if veri_baytlari.startswith(b"{\\rtf"):
        return True, "rtf"

    # 21. android dex ikilisi.
    if veri_baytlari.startswith(b"dex\n"):
        return True, "dex"

    # 22. pcap ağ yakalama dosyası.
    if veri_baytlari.startswith((b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\n\r\r\n")):
        return True, "pcap"

    # 23. bmp ve gif resmi.
    if veri_baytlari.startswith(b"BM") and len(veri_baytlari) >= 14:
        return True, "bmp"
    if veri_baytlari.startswith((b"GIF87a", b"GIF89a")):
        return True, "gif"

    # 24. genel yapısal ikili veri.
    if ki_kare_yapisal_test(veri_baytlari):
        ozel_bilinenler = (
            "txt", "enc", "locked", "crypto", "djvu", "ransom",
            "xml", "html", "htm", "json", "csv", "pdf", "png",
            "jpg", "jpeg", "zip", "docx", "xlsx", "pptx", "exe", "elf",
            "mp4", "mp3", "7z", "rar", "tar_gz", "bzip2", "xz", "zst"
        )
        if beklenen_tur and beklenen_tur.lower() not in ozel_bilinenler:
            return True, beklenen_tur.lower()
        if not beklenen_tur or beklenen_tur.lower() in ("bin", "dat", "db", "mdf", "raw", "data"):
            return True, "bin_yapisal"

    return False, None


def ki_kare_yapisal_test(veri: bytes) -> bool:
    """
    şifreli rastgele veri (high entropy noise) ile yapısal/özel binary formatları ayırt eder.
    gerçek binary dosyalarda (veritabanı, tescilli format, bayt dizilimleri)
    0x00, 0x20 gibi dolgu baytları sıkça geçer ve bayt dağılımı üniform değildir.
    """
    if not veri or len(veri) < 128:
        return False
    blok = veri[:min(len(veri), 16384)]
    uzunluk = len(blok)
    beklenen = uzunluk / 256.0
    sayim = [0] * 256
    for b in blok:
        sayim[b] += 1
    ki_kare = sum(((c - beklenen) ** 2) / beklenen for c in sayim)
    sifir_orani = sayim[0] / uzunluk
    ent = shannon_entropisi_hesapla(blok)
    if (ki_kare > 600.0 or sifir_orani > 0.03) and ent <= 7.85:
        return True
    return False


def dosya_baslik_analizi_yap(dosya_yolu: str) -> Dict[str, any]:
    # dosya başlığı ve yapısından bozulma durumunu analiz eder.
    if not os.path.exists(dosya_yolu):
        return {"hata": "dosya bulunamadi"}

    dosya_boyutu = os.path.getsize(dosya_yolu)
    okunacak_boyut = min(dosya_boyutu, 512)

    with open(dosya_yolu, "rb") as dosya_nesnesi:
        ilk_baytlar = dosya_nesnesi.read(okunacak_boyut)
        son_baytlar = b""
        if dosya_boyutu > 512:
            dosya_nesnesi.seek(max(0, dosya_boyutu - 512))
            son_baytlar = dosya_nesnesi.read(512)

    tespit_edilen_tur = sihirli_baytlardan_tur_tahmin_et(ilk_baytlar)
    dosya_uzantisi = os.path.splitext(dosya_yolu)[1].lower().lstrip(".")

    baslik_bozulmus_mu = False
    if dosya_uzantisi in BILINEN_SIHIRLI_BAYTLAR:
        beklenen_imza = BILINEN_SIHIRLI_BAYTLAR[dosya_uzantisi]
        if not ilk_baytlar.startswith(beklenen_imza):
            baslik_bozulmus_mu = True

    # dosya sonu özel işaretçi kontrolü.
    ozel_son_ek_var_mi = False
    if son_baytlar:
        ascii_karakterler = [bayt for bayt in son_baytlar if 32 <= bayt <= 126]
        if len(ascii_karakterler) > 20:
            ozel_son_ek_var_mi = True

    return {
        "dosya_yolu": dosya_yolu,
        "dosya_boyutu": dosya_boyutu,
        "mevcut_uzanti": dosya_uzantisi,
        "tespit_edilen_tur": tespit_edilen_tur,
        "baslik_bozulmus_mu": baslik_bozulmus_mu,
        "ilk_16_bayt_hex": ilk_baytlar[:16].hex(),
        "ozel_son_ek_var_mi": ozel_son_ek_var_mi
    }
