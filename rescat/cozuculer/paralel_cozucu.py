import os
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import Dict, List, Optional
from rescat.cozuculer.temel_cozucu import TemelCozucu
from rescat.cozuculer.evrensel_cozucu import CozucuFabrikasi


def _tekil_paralel_gorev(parametreler: tuple) -> Dict[str, any]:
    # çoklu işlem havuzu için tekil dosya çözüm görevi.
    dosya_yolu, algoritma, anahtar_baytlari, mod_adi, iv, kuru_calistirma, yedek_al, cikti_dizini = parametreler

    try:
        cozucu = CozucuFabrikasi.cozucu_uret(
            algoritma=algoritma,
            anahtar_baytlari=anahtar_baytlari,
            mod=mod_adi,
            iv=iv,
            kuru_calistirma=kuru_calistirma,
            yedek_al=yedek_al,
            hedef_cikti_dizini=cikti_dizini
        )
        return cozucu.tekil_dosya_coz(dosya_yolu)
    except Exception as hata_detayi:
        return {"dosya": dosya_yolu, "basarili": False, "hata": str(hata_detayi)}


class ParalelCozucu:
    # çok çekirdekli paralel çözme motoru.
    def __init__(
        self,
        anahtar_baytlari: bytes,
        algoritma: str = "aes",
        mod_adi: str = "cbc",
        baslatma_vektoru: Optional[bytes] = None,
        is_parcacigi_sayisi: Optional[int] = None,
        kuru_calistirma: bool = False,
        yedek_al: bool = True,
        hedef_cikti_dizini: Optional[str] = None
    ) -> None:
        # paralel çözücü yapılandırmasını tanımlar.
        self.anahtar_baytlari: bytes = anahtar_baytlari
        self.algoritma: str = algoritma.lower()
        self.mod_adi: str = mod_adi.lower()
        self.baslatma_vektoru: Optional[bytes] = baslatma_vektoru
        self.is_parcacigi_sayisi: int = is_parcacigi_sayisi or (os.cpu_count() or 4)
        self.kuru_calistirma: bool = kuru_calistirma
        self.yedek_al: bool = yedek_al
        self.hedef_cikti_dizini: Optional[str] = hedef_cikti_dizini

    def dizini_paralel_coz(self, hedef_dizin: str, uzanti_filtresi: Optional[str] = None) -> List[Dict[str, any]]:
        # dizindeki dosyaları çok çekirdekle paralel çözer.
        dosya_listesi: List[str] = []

        for kok_dizin, _, dosya_isimleri in os.walk(hedef_dizin):
            for dosya_adi in dosya_isimleri:
                if uzanti_filtresi and not dosya_adi.endswith(uzanti_filtresi):
                    continue
                if dosya_adi.endswith(".bak"):
                    continue
                dosya_listesi.append(os.path.join(kok_dizin, dosya_adi))

        if not dosya_listesi:
            return []

        gorev_parametreleri = [
            (
                dosya,
                self.algoritma,
                self.anahtar_baytlari,
                self.mod_adi,
                self.baslatma_vektoru,
                self.kuru_calistirma,
                self.yedek_al,
                self.hedef_cikti_dizini
            )
            for dosya in dosya_listesi
        ]

        sonuclar: List[Dict[str, any]] = []
        with ProcessPoolExecutor(max_workers=self.is_parcacigi_sayisi) as havuz:
            gelecek_gorevler = [havuz.submit(_tekil_paralel_gorev, p) for p in gorev_parametreleri]
            for gorev in as_completed(gelecek_gorevler):
                sonuclar.append(gorev.result())

        return sonuclar
