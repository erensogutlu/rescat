import os
import math
from typing import Dict, List, Optional, Tuple, Any
from rescat.cekirdek.entropi import shannon_entropisi_hesapla
from rescat.cekirdek.dosya_tanimlayici import format_icerik_dogrula


class AralikliSifreMotoru:
    """
    lockbit 3.0, blackcat/alphv, play ve black basta gibi modern
    fidye yazilimlarinin kullandigi aralikli (intermittent / stride)
    sifreleme modelini analiz eden, tespit eden ve cozen motor.
    """
    def __init__(
        self,
        kuru_calistirma: bool = False,
        yedek_al: bool = True,
        hedef_cikti_dizini: Optional[str] = None
    ) -> None:
        self.kuru_calistirma = kuru_calistirma
        self.yedek_al = yedek_al
        self.hedef_cikti_dizini = hedef_cikti_dizini

    @staticmethod
    def blok_entropi_haritasi_cikar(
        dosya_yolu: str,
        blok_boyutu: int = 512,
        maks_boyut: int = 10 * 1024 * 1024
    ) -> List[Tuple[int, float, bool]]:
        """
        dosyanin her blok_boyutu kadarlik kisminin entropisini hesaplar.
        entropi >= 7.6 ise sifreli kabul edilir.
        dondurur: [(ofset, entropi, sifreli_mi), ...]
        """
        harita = []
        with open(dosya_yolu, "rb") as f:
            ofset = 0
            while ofset < maks_boyut:
                parca = f.read(blok_boyutu)
                if not parca:
                    break
                entropi = shannon_entropisi_hesapla(parca)
                sifreli_mi = (entropi >= 7.55 and len(parca) >= 64)
                harita.append((ofset, entropi, sifreli_mi))
                ofset += len(parca)
        return harita

    @classmethod
    def aralikli_patern_tespit_et(cls, dosya_yolu: str) -> Dict[str, Any]:
        """
        dosyadaki sifreli/sifresiz blok gecislerini analiz ederek
        sifreleme paternini tespit eder (sifreli_blok_boyutu, atlama_boyutu).
        """
        harita = cls.blok_entropi_haritasi_cikar(dosya_yolu, blok_boyutu=64)
        if len(harita) < 4:
            return {"aralikli_mi": False, "sebep": "Dosya cok kisa"}

        sifreli_blok_sayisi = sum(1 for _, _, s in harita if s)
        toplam_blok = len(harita)
        sifreli_oran = sifreli_blok_sayisi / toplam_blok

        # tümü şifreli veya açıksa aralıklı değildir.
        if sifreli_oran > 0.95:
            return {"aralikli_mi": False, "tur": "tam_sifreli", "oran": sifreli_oran}
        if sifreli_oran < 0.05:
            return {"aralikli_mi": False, "tur": "acik_metin", "oran": sifreli_oran}

        # geçiş noktalarını ve ortalama blok uzunluklarını bulur.
        durum_uzunluklari = []
        mevcut_durum = harita[0][2]
        mevcut_boyut = 64

        for _, _, s in harita[1:]:
            if s == mevcut_durum:
                mevcut_boyut += 64
            else:
                durum_uzunluklari.append((mevcut_durum, mevcut_boyut))
                mevcut_durum = s
                mevcut_boyut = 64
        durum_uzunluklari.append((mevcut_durum, mevcut_boyut))

        sifreli_uzunluklar = [boyut for sifreli, boyut in durum_uzunluklari if sifreli]
        acik_uzunluklar = [boyut for sifreli, boyut in durum_uzunluklari if not sifreli]

        ort_sifreli = int(sum(sifreli_uzunluklar) / len(sifreli_uzunluklar)) if sifreli_uzunluklar else 0
        ort_acik = int(sum(acik_uzunluklar) / len(acik_uzunluklar)) if acik_uzunluklar else 0

        return {
            "aralikli_mi": True,
            "sifreli_oran": sifreli_oran,
            "tahmini_sifreli_adim": ort_sifreli,
            "tahmini_atlama_adim": ort_acik,
            "gecis_sayisi": len(durum_uzunluklari)
        }

    def aralikli_dosya_coz(
        self,
        dosya_yolu: str,
        cozucu_fonksiyonu,
        sifreli_adim: int,
        atlama_adim: int
    ) -> Dict[str, Any]:
        """
        belirlenen adim/atlama paternine gore sadece sifreli araliklari cozup
        acik metin araliklariyla birlestirerek dosyayi tam rekonstrue eder.
        """
        try:
            with open(dosya_yolu, "rb") as f:
                veri = f.read()

            toplam_uzunluk = len(veri)
            cozulmus_veri = bytearray(toplam_uzunluk)
            imlec = 0

            while imlec < toplam_uzunluk:
                # 1. şifreli parça.
                sifreli_parca_sonu = min(imlec + sifreli_adim, toplam_uzunluk)
                sifreli_parca = veri[imlec:sifreli_parca_sonu]
                
                try:
                    cozulmus_parca = cozucu_fonksiyonu(sifreli_parca)
                    cozulmus_veri[imlec:imlec + len(cozulmus_parca)] = cozulmus_parca
                except Exception:
                    cozulmus_veri[imlec:sifreli_parca_sonu] = sifreli_parca

                imlec = sifreli_parca_sonu

                # 2. atlanan düz metin parça.
                atlama_sonu = min(imlec + atlama_adim, toplam_uzunluk)
                cozulmus_veri[imlec:atlama_sonu] = veri[imlec:atlama_sonu]
                imlec = atlama_sonu

            gecerli, tur = format_icerik_dogrula(bytes(cozulmus_veri[:2048]))

            hedef_yol = dosya_yolu
            if not self.kuru_calistirma:
                if self.hedef_cikti_dizini:
                    os.makedirs(self.hedef_cikti_dizini, exist_ok=True)
                    hedef_yol = os.path.join(self.hedef_cikti_dizini, os.path.basename(dosya_yolu))
                elif self.yedek_al:
                    yedek = dosya_yolu + ".bak"
                    if not os.path.exists(yedek):
                        import shutil
                        shutil.copy2(dosya_yolu, yedek)

                with open(hedef_yol, "wb") as f_out:
                    f_out.write(cozulmus_veri)

            return {
                "basarili": True,
                "dosya": dosya_yolu,
                "hedef_yol": hedef_yol,
                "dogrulanan_tur": tur,
                "boyut": len(cozulmus_veri)
            }
        except Exception as e:
            return {"basarili": False, "dosya": dosya_yolu, "hata": str(e)}

    def acik_metin_dilimlerini_kurtar(self, dosya_yolu: str, cikti_klasoru: str) -> Dict[str, Any]:
        """
        anahtar bulunamasa dahi aralikli sifreleme sonucu dokunulmamis
        acik metin bloklarini ve icerisindeki gecerli dosya/sayfa yapilarini kurtarir.
        """
        os.makedirs(cikti_klasoru, exist_ok=True)
        kurtarilan_parcalar = []

        with open(dosya_yolu, "rb") as f:
            veri = f.read()

        harita = self.blok_entropi_haritasi_cikar(dosya_yolu, blok_boyutu=512)
        acik_blok_ofsetleri = [ofset for ofset, _, sifreli in harita if not sifreli]

        # ardışık açık blokları birleştirir.
        if acik_blok_ofsetleri:
            baslangic = acik_blok_ofsetleri[0]
            onceki = baslangic
            for ofs in acik_blok_ofsetleri[1:]:
                if ofs == onceki + 512:
                    onceki = ofs
                else:
                    dilim = veri[baslangic:onceki + 512]
                    if len(dilim) >= 1024:
                        parca_adi = f"kurtarilan_ofset_{baslangic}_{len(dilim)}B.raw"
                        parca_yolu = os.path.join(cikti_klasoru, parca_adi)
                        with open(parca_yolu, "wb") as pf:
                            pf.write(dilim)
                        kurtarilan_parcalar.append(parca_yolu)
                    baslangic = ofs
                    onceki = ofs
            # son parça.
            dilim = veri[baslangic:onceki + 512]
            if len(dilim) >= 1024:
                parca_adi = f"kurtarilan_ofset_{baslangic}_{len(dilim)}B.raw"
                parca_yolu = os.path.join(cikti_klasoru, parca_adi)
                with open(parca_yolu, "wb") as pf:
                    pf.write(dilim)
                kurtarilan_parcalar.append(parca_yolu)

        return {
            "basarili": len(kurtarilan_parcalar) > 0,
            "kurtarilan_parca_sayisi": len(kurtarilan_parcalar),
            "parcalar": kurtarilan_parcalar
        }
