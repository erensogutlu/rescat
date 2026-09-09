import os
import shutil
from typing import Dict, Optional, Tuple
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from rescat.cozuculer.temel_cozucu import TemelCozucu
from rescat.cekirdek.djvu_veritabani import (
    uzantiya_gore_offline_anahtar_al,
    offline_anahtar_mi,
    VARSAYILAN_OFFLINE_ANAHTAR_HEX
)
from rescat.cekirdek.dosya_tanimlayici import sihirli_baytlardan_tur_tahmin_et


class DjvuCozucu(TemelCozucu):
    # stop/djvu çevrim dışı anahtarlarla çözme motoru.
    def __init__(
        self,
        anahtar_baytlari: Optional[bytes] = None,
        kuru_calistirma: bool = False,
        yedek_al: bool = True,
        hedef_cikti_dizini: Optional[str] = None
    ) -> None:
        super().__init__(
            kuru_calistirma=kuru_calistirma,
            yedek_al=yedek_al,
            hedef_cikti_dizini=hedef_cikti_dizini
        )
        self.anahtar_baytlari: Optional[bytes] = anahtar_baytlari

    def baytlari_coz(self, sifreli_baytlar: bytes) -> bytes:
        # varsayılan anahtarla blok çözme.
        anahtar = self.anahtar_baytlari or bytes.fromhex(VARSAYILAN_OFFLINE_ANAHTAR_HEX)
        # stop/djvu ilk 150 kb kısmı şifreler.
        iv = b"\x00" * 16
        sifreleyici = Cipher(algorithms.AES(anahtar), modes.CBC(iv), backend=default_backend()).decryptor()
        return sifreleyici.update(sifreli_baytlar) + sifreleyici.finalize()

    def kurban_isaretcisini_ayristir(self, veri: bytes) -> Tuple[Optional[str], int]:
        # dosya sonundaki djvu kurban id işaretçisini arar.
        # stop/djvu kurban id kontrolü.
        if len(veri) < 32:
            return None, 0

        kuyruk = veri[-64:]
        # t1 veya t2 çevrim dışı kurban kimliği.
        import re
        eslesme = re.search(rb"([a-zA-Z0-9]{32,40}(?:t1|t2))", kuyruk)
        if eslesme:
            kurban_id = eslesme.group(1).decode("ascii", errors="ignore")
            kesme_boyutu = len(veri) - (len(kuyruk) - kuyruk.find(eslesme.group(1)))
            return kurban_id, kesme_boyutu

        return None, len(veri)

    def tekil_dosya_coz(self, dosya_yolu: str, animasyon: bool = False) -> Dict[str, any]:
        # stop/djvu dosyasını kısmi deşifreleme ile kurtarır.
        if not os.path.exists(dosya_yolu):
            return {"dosya": dosya_yolu, "basarili": False, "hata": "dosya bulunamadi"}

        try:
            with open(dosya_yolu, "rb") as dosya_nesnesi:
                ham_veri = dosya_nesnesi.read()

            if len(ham_veri) < 16:
                return {"dosya": dosya_yolu, "basarili": False, "hata": "dosya cok kucuk"}

            # dosya uzantısına göre anahtar belirler.
            uzanti = os.path.splitext(dosya_yolu)[1]
            anahtar_hex = uzantiya_gore_offline_anahtar_al(uzanti)
            anahtar = self.anahtar_baytlari or bytes.fromhex(anahtar_hex or VARSAYILAN_OFFLINE_ANAHTAR_HEX)

            # kurban id kontrolü.
            kurban_id, kesme_noktasi = self.kurban_isaretcisini_ayristir(ham_veri)

            # stop/djvu ilk 150 kb veya tam dosya şifrelemesi.
            sifreli_blok_uzunlugu = min(153600, kesme_noktasi)
            # 16 baytın katı olmalıdır.
            blok_kat = (sifreli_blok_uzunlugu // 16) * 16
            if blok_kat == 0:
                blok_kat = len(ham_veri)

            sifreli_kisim = ham_veri[:blok_kat]
            kalan_saglam_kisim = ham_veri[blok_kat:kesme_noktasi]

            # aes-cbc ile çözmeyi dener.
            iv = b"\x00" * 16
            sifreleyici = Cipher(algorithms.AES(anahtar), modes.CBC(iv), backend=default_backend()).decryptor()
            cozulmus_blok = sifreleyici.update(sifreli_kisim) + sifreleyici.finalize()

            kurtarilan_tam_veri = cozulmus_blok + kalan_saglam_kisim
            dogrulanan_tur = sihirli_baytlardan_tur_tahmin_et(kurtarilan_tam_veri[:32])

            if self.kuru_calistirma:
                return {
                    "dosya": dosya_yolu,
                    "basarili": True,
                    "kuru_calistirma": True,
                    "kurban_id": kurban_id,
                    "dogrulanan_tur": dogrulanan_tur,
                    "cozulen_boyut": len(kurtarilan_tam_veri)
                }

            if self.hedef_cikti_dizini:
                os.makedirs(self.hedef_cikti_dizini, exist_ok=True)
                hedef_yol = os.path.join(self.hedef_cikti_dizini, os.path.basename(dosya_yolu))
            else:
                hedef_yol = dosya_yolu
                if self.yedek_al:
                    yedek_yolu = dosya_yolu + ".bak"
                    if not os.path.exists(yedek_yolu):
                        shutil.copy2(dosya_yolu, yedek_yolu)

            with open(hedef_yol, "wb") as cikti_dosyasi:
                cikti_dosyasi.write(kurtarilan_tam_veri)

            return {
                "dosya": dosya_yolu,
                "hedef_yol": hedef_yol,
                "basarili": True,
                "kurban_id": kurban_id,
                "dogrulanan_tur": dogrulanan_tur,
                "cozulen_boyut": len(kurtarilan_tam_veri)
            }
        except Exception as hata_detayi:
            return {
                "dosya": dosya_yolu,
                "basarili": False,
                "hata": str(hata_detayi)
            }
