import os
import shutil
from abc import ABC, abstractmethod
from typing import Dict, List, Optional
from rescat.cekirdek.dosya_tanimlayici import sihirli_baytlardan_tur_tahmin_et, format_icerik_dogrula


class TemelCozucu(ABC):
    # tüm deşifreleme modülleri için ortak temel sınıf.
    def __init__(
        self,
        kuru_calistirma: bool = False,
        yedek_al: bool = True,
        hedef_cikti_dizini: Optional[str] = None
    ) -> None:
        # temel çözücü yapılandırmasını tanımlar.
        self.kuru_calistirma: bool = kuru_calistirma
        self.yedek_al: bool = yedek_al
        self.hedef_cikti_dizini: Optional[str] = hedef_cikti_dizini

    @abstractmethod
    def baytlari_coz(self, sifreli_baytlar: bytes) -> bytes:
        # alt sınıfların uygulayacağı bayt çözme metodu.
        pass

    def cozulen_veriyi_dogrula(self, cozulmus_baytlar: bytes) -> Optional[str]:
        # çözülen verinin format geçerliliğini denetler.
        gecerli, tur = format_icerik_dogrula(cozulmus_baytlar)
        if gecerli and tur:
            return tur
        return None

    def tekil_dosya_coz(self, dosya_yolu: str, animasyon: bool = False) -> Dict[str, any]:
        # tek dosyanın şifresini güvenle çözer.
        if not os.path.exists(dosya_yolu):
            return {"dosya": dosya_yolu, "basarili": False, "hata": "dosya bulunamadi"}

        try:
            with open(dosya_yolu, "rb") as dosya_nesnesi:
                sifreli_baytlar = dosya_nesnesi.read()

            cozulmus_baytlar = self.baytlari_coz(sifreli_baytlar)
            dogrulanan_tur = self.cozulen_veriyi_dogrula(cozulmus_baytlar)

            if self.kuru_calistirma:
                return {
                    "dosya": dosya_yolu,
                    "basarili": True,
                    "kuru_calistirma": True,
                    "dogrulanan_tur": dogrulanan_tur,
                    "cozulen_boyut": len(cozulmus_baytlar)
                }

            # çıktı yolunu belirler.
            if self.hedef_cikti_dizini:
                os.makedirs(self.hedef_cikti_dizini, exist_ok=True)
                hedef_yol = os.path.join(self.hedef_cikti_dizini, os.path.basename(dosya_yolu))
                with open(hedef_yol, "wb") as cikti_dosyasi:
                    cikti_dosyasi.write(cozulmus_baytlar)
                if self.yedek_al and os.path.abspath(hedef_yol) != os.path.abspath(dosya_yolu):
                    yedek_yolu = dosya_yolu + ".bak"
                    if not os.path.exists(yedek_yolu):
                        shutil.copy2(dosya_yolu, yedek_yolu)
                    with open(dosya_yolu, "wb") as f_orj:
                        f_orj.write(cozulmus_baytlar)
            else:
                hedef_yol = dosya_yolu
                if self.yedek_al:
                    yedek_yolu = dosya_yolu + ".bak"
                    if not os.path.exists(yedek_yolu):
                        shutil.copy2(dosya_yolu, yedek_yolu)
                with open(hedef_yol, "wb") as cikti_dosyasi:
                    cikti_dosyasi.write(cozulmus_baytlar)

            if animasyon:
                from rescat.yardimcilar.konsol import sifre_cozme_animasyonu_oynat
                algo_adi = getattr(self, "algoritma_adi", self.__class__.__name__.replace("Cozucu", ""))
                sifre_cozme_animasyonu_oynat(
                    dosya_adi=os.path.basename(dosya_yolu),
                    algoritma=algo_adi,
                    hedef_yol=hedef_yol
                )

            return {
                "dosya": dosya_yolu,
                "hedef_yol": hedef_yol,
                "basarili": True,
                "dogrulanan_tur": dogrulanan_tur,
                "cozulen_boyut": len(cozulmus_baytlar)
            }
        except Exception as hata_mesaji:
            return {
                "dosya": dosya_yolu,
                "basarili": False,
                "hata": str(hata_mesaji)
            }

    def dizin_coz(self, hedef_dizin: str, uzanti_filtresi: Optional[str] = None) -> List[Dict[str, any]]:
        # dizindeki dosyaları özyinelemeli çözer.
        sonuclar: List[Dict[str, any]] = []

        for kok_dizin, _, dosya_isimleri in os.walk(hedef_dizin):
            for dosya_adi in dosya_isimleri:
                if uzanti_filtresi and not dosya_adi.endswith(uzanti_filtresi):
                    continue
                # yedek dosyalarını atlar.
                if dosya_adi.endswith(".bak"):
                    continue

                tam_yol = os.path.join(kok_dizin, dosya_adi)
                sonuc = self.tekil_dosya_coz(tam_yol)
                sonuclar.append(sonuc)

        return sonuclar
