import re
from typing import Dict, Any, Optional, List
from rescat.cekirdek.entropi import shannon_entropisi_hesapla


class FooterAyristirici:
    """
    fidye yazılımlarının dosya sonuna eklediği şifreli oturum anahtarları (rsa/ecc blobları),
    kurban kimlikleri (victim ıd), yapılandırma bayrakları ve özel işaretçileri
    (marker/magic footer) ayrıştıran adli analiz modülü.
    """

    # bilinen dosya sonu işaretçileri.
    BILINEN_ISARETCILER = [
        (rb"\{[a-fA-F0-9\-]{36}\}", "Standard GUID / Kurban ID"),
        (rb"\{[a-fA-F0-9]{32,40}(?:t1|t2)\}", "STOP/Djvu Kurban ID (Offline/Online)"),
        (rb"[a-fA-F0-9]{32,40}(?:t1|t2)", "STOP/Djvu Ham Kurban ID"),
        (rb"LockBit", "LockBit Marker"),
        (rb"ALPHV", "BlackCat / ALPHV Marker"),
        (rb"Babuk", "Babuk Marker"),
        (rb"Conti", "Conti Marker"),
        (rb"Phobos", "Phobos / Dharma Marker"),
    ]

    def __init__(self, kuyruk_boyutu: int = 2048) -> None:
        self.kuyruk_boyutu = kuyruk_boyutu

    def dosyayi_ayristir(self, dosya_yolu: str) -> Dict[str, Any]:
        """dosyanın son 2048 baytını inceleyerek gömülü metadata ve anahtar bloklarını çıkarır."""
        try:
            with open(dosya_yolu, "rb") as f:
                f.seek(0, 2)
                toplam_boyut = f.tell()
                okunacak = min(self.kuyruk_boyutu, toplam_boyut)
                f.seek(toplam_boyut - okunacak)
                kuyruk = f.read(okunacak)

            return self.kuyruk_baytlarini_ayristir(kuyruk, toplam_boyut)

        except Exception as e:
            return {"basarili": False, "hata": str(e)}

    def kuyruk_baytlarini_ayristir(self, kuyruk: bytes, toplam_boyut: int) -> Dict[str, Any]:
        bulunan_isaretciler: List[Dict[str, Any]] = []
        kurban_id: Optional[str] = None
        olasi_rsa_anahtar_blobu: Optional[Dict[str, Any]] = None

        # 1. işaretçi ve kurban kimliği taraması.
        for desen, aciklama in self.BILINEN_ISARETCILER:
            eslesmeler = list(re.finditer(desen, kuyruk))
            for eslesme in eslesmeler:
                bulunan_metin = eslesme.group(0).decode("latin1", errors="ignore")
                bulunan_isaretciler.append({
                    "isaretci": bulunan_metin,
                    "tip": aciklama,
                    "kuyruk_ofseti": eslesme.start()
                })
                if "ID" in aciklama and kurban_id is None:
                    kurban_id = bulunan_metin

        # 2. şifreli asimetrik oturum anahtarı bloğu tespiti.
        # dosya sonu öncesindeki yüksek entropili blok analizi.
        kuyruk_len = len(kuyruk)
        for rsa_boyutu in (512, 256, 128):
            if kuyruk_len >= rsa_boyutu:
                # son n bayt veya kimlik öncesi bayt aralığı.
                aday_blok = kuyruk[-rsa_boyutu:]
                ent = shannon_entropisi_hesapla(aday_blok)
                if ent >= 7.60:  # şifreli veri entropi kontrolü.
                    olasi_rsa_anahtar_blobu = {
                        "boyut_bayt": rsa_boyutu,
                        "tahmini_asimetrik_tip": f"RSA-{rsa_boyutu * 8} / ECC Encrypted Session Key",
                        "entropi": round(ent, 3),
                        "onizleme_hex": aday_blok[:32].hex() + "..."
                    }
                    break

        return {
            "basarili": True,
            "toplam_dosya_boyutu": toplam_boyut,
            "incelenen_kuyruk_bayt": len(kuyruk),
            "kurban_id": kurban_id,
            "bulunan_isaretciler": bulunan_isaretciler,
            "olasi_asimetrik_anahtar_blobu": olasi_rsa_anahtar_blobu,
            "onerilen_strateji": (
                "Dosya sonu asimetrik oturum anahtarı içeriyor. Bellek dökümünden simetrik anahtarı avlayın "
                "veya sızdırılmış özel RSA anahtarı ile footer bloğunu çözün."
                if olasi_rsa_anahtar_blobu else "Standart simetrik şifre çözme motoru kullanılabilir."
            )
        }
