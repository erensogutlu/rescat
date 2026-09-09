import os
import shutil
import math
import struct
from typing import Dict, List, Optional, Any, Tuple, Callable
from rescat.cekirdek.dosya_tanimlayici import (
    sihirli_baytlardan_tur_tahmin_et,
    format_icerik_dogrula,
    BILINEN_SIHIRLI_BAYTLAR
)
from rescat.cekirdek.entropi import shannon_entropisi_hesapla
from rescat.yardimcilar.konsol import (
    YuklenmeCubugu,
    bilgi_yaz,
    basari_yaz,
    uyari_yaz,
    dengeli_bekle,
    tablo_satiri_yaz
)


class OtonomAlgoritmaUretici:
    """
    standart kripto çözücüler (aes, chacha, stop/djvu, bilinen xor vb.) başarısız olduğunda,
    şifreli dosyanın entropi, bayt dağılımı ve format yapısını analiz ederek
    otonom olarak özel şifre çözme algoritmaları sentezleyen ve uygulayan motor.
    """

    def __init__(
        self,
        kuru_calistirma: bool = False,
        yedek_al: bool = True,
        hedef_cikti_dizini: Optional[str] = None
    ) -> None:
        self.kuru_calistirma: bool = kuru_calistirma
        self.yedek_al: bool = yedek_al
        self.hedef_cikti_dizini: Optional[str] = hedef_cikti_dizini

    @staticmethod
    def _rol8(bayt: int, n: int) -> int:
        return ((bayt << n) & 0xFF) | (bayt >> (8 - n))

    @staticmethod
    def _ror8(bayt: int, n: int) -> int:
        return (bayt >> n) | ((bayt << (8 - n)) & 0xFF)

    @staticmethod
    def _nibble_swap(bayt: int) -> int:
        return ((bayt & 0x0F) << 4) | ((bayt & 0xF0) >> 4)

    def _aday_skor_hesapla(self, veri: bytes, beklenen_format: Optional[str] = None) -> Tuple[float, Optional[str]]:
        """
        üretilen aday veri için kalite ve format doğruluğu skoru hesaplar (0 - 100).
        sert yapısal doğrulama (structural verification) uygular.
        rastgele gürültü / kırılmamış şifreli veri için kesinlikle 0.0 döner.
        """
        if not veri or len(veri) < 8:
            return 0.0, None

        ent = shannon_entropisi_hesapla(veri[:4096])

        # 1. tam yapısal doğrulama.
        gecerli, dogrulanan_tur = format_icerik_dogrula(veri, beklenen_tur=beklenen_format)
        if gecerli and dogrulanan_tur:
            if beklenen_format and beklenen_format.lower() not in ("locked", "enc", "crypto", "djvu", "ransom", ""):
                if dogrulanan_tur.lower() == beklenen_format.lower():
                    return 100.0, dogrulanan_tur
                elif dogrulanan_tur in ("zip", "docx", "xlsx", "pptx") and beklenen_format.lower() in ("zip", "docx", "xlsx", "pptx"):
                    return 95.0, dogrulanan_tur
                elif dogrulanan_tur != "txt":
                    return 85.0, dogrulanan_tur
                else:
                    return 0.0, None
            if dogrulanan_tur != "txt":
                return 90.0, dogrulanan_tur
            return 70.0, dogrulanan_tur

        # 2. yüksek entropili doğrulanmamış veriyi reddeder.
        if ent > 7.80:
            return 0.0, None

        # 3. metin ve yapısal ascii analizi.
        if beklenen_format and beklenen_format.lower() not in (
            "txt", "csv", "json", "xml", "log", "html", "htm", "sql", "py",
            "c", "cpp", "sh", "bat", "ps1", "md", "yaml", "yml", "ini", "cfg",
            "locked", "enc", "crypto", "djvu", "ransom", ""
        ):
            return 0.0, None

        ilk_blok = veri[:min(len(veri), 1024)]
        basilabilir = sum(1 for b in ilk_blok if 32 <= b <= 126 or b in (9, 10, 13))
        oran = basilabilir / max(1, len(ilk_blok))
        if oran >= 0.95 and ent <= 6.5:
            return 80.0, "txt"

        return 0.0, None

    def algoritma_sentezle_ve_coz(
        self,
        dosya_yolu: str,
        cubuk: Optional[YuklenmeCubugu] = None
    ) -> Dict[str, Any]:
        """
        şifreli dosya için dinamik olarak aday algoritmalar türetir, test eder,
        en yüksek puanlı algoritmayı seçer ve dosyayı kurtarır.
        """
        if not os.path.exists(dosya_yolu):
            return {"basarili": False, "hata": "Dosya bulunamadı"}

        dosya_adi = os.path.basename(dosya_yolu)
        uzanti = os.path.splitext(dosya_yolu)[1].lstrip(".").lower()

        try:
            with open(dosya_yolu, "rb") as f:
                ham_veri = f.read()
        except Exception as e:
            return {"basarili": False, "hata": f"Dosya okunamadı: {e}"}

        toplam_boyut = len(ham_veri)
        if toplam_boyut == 0:
            return {"basarili": False, "hata": "Dosya boş"}

        harici_cubuk = cubuk is not None
        if not cubuk:
            cubuk = YuklenmeCubugu(toplam=100, baslik="Şifre Çözülüyor", dosya_adi=dosya_adi)

        cubuk.guncelle(80, asama="Otonom Algoritma Sentezleniyor")
        dengeli_bekle(0.06)

        ilk_parca = ham_veri[: min(8192, toplam_boyut)]
        en_iyi_skor = 0.0
        en_iyi_cozum_baytlari: Optional[bytes] = None
        en_iyi_algoritma_adi: str = ""
        en_iyi_tur: Optional[str] = None

        # 1. sihirli bayt türetimi ve ters dönüşüm haritalama.
        cubuk.guncelle(80 if harici_cubuk else 25, asama="Kombinatorik dönüşüm uzayı taranıyor")
        dengeli_bekle(0.06)

        # aday 1: dinamik başlık ve akış rekonstrüksiyonu.
        guvenli_imzalar = {
            fmt: imza for fmt, imza in BILINEN_SIHIRLI_BAYTLAR.items()
            if len(imza) >= 4 and fmt not in ("exe", "tar_gz")
        }

        for fmt_adi, imza in guvenli_imzalar.items():
            konum = ham_veri.find(imza, 16)
            if 16 <= konum <= 65536:
                aday_govde = ham_veri[konum:]
                gecerli, dogrulanan_tur = format_icerik_dogrula(aday_govde, beklenen_tur=fmt_adi)
                if gecerli and dogrulanan_tur:
                    skor_govde, tur_govde = self._aday_skor_hesapla(aday_govde, fmt_adi)
                    if skor_govde > en_iyi_skor and skor_govde >= 70.0:
                        en_iyi_skor = skor_govde
                        en_iyi_tur = dogrulanan_tur
                        en_iyi_algoritma_adi = f"Zarf-Sıyırma-ve-Ofset-Rekonstrüksiyonu(+{konum} Bayt)"
                        en_iyi_cozum_baytlari = aday_govde
                        break

        # aday 2: modüler toplama ve çıkarma sentezi.
        if en_iyi_skor < 95.0:
            for k in range(1, 256):
                aday = bytes((b - k) % 256 for b in ilk_parca)
                skor, tur = self._aday_skor_hesapla(aday, uzanti)
                if skor > en_iyi_skor:
                    en_iyi_skor = skor
                    en_iyi_tur = tur
                    en_iyi_algoritma_adi = f"Dinamik-Modüler-Çıkarma(Key=0x{k:02X})"
                    en_iyi_cozum_baytlari = bytes((b - k) % 256 for b in ham_veri)
                    if skor >= 95.0:
                        break

        # aday 3: bit rotasyonu ve dinamik xor sentezi.
        if en_iyi_skor < 95.0:
            cubuk.guncelle(85 if harici_cubuk else 45, asama="Bit rotasyonu ve S-Box tabloları sentezleniyor")
            dengeli_bekle(0.06)

            for shift in range(1, 8):
                # ror kaydırma işlemi.
                aday_ror = bytes(self._ror8(b, shift) for b in ilk_parca)
                skor_ror, tur_ror = self._aday_skor_hesapla(aday_ror, uzanti)
                if skor_ror > en_iyi_skor:
                    en_iyi_skor = skor_ror
                    en_iyi_tur = tur_ror
                    en_iyi_algoritma_adi = f"Dinamik-BitRotasyon-ROR({shift})"
                    en_iyi_cozum_baytlari = bytes(self._ror8(b, shift) for b in ham_veri)
                    if skor_ror >= 95.0:
                        break

                # rol kaydırma işlemi.
                aday_rol = bytes(self._rol8(b, shift) for b in ilk_parca)
                skor_rol, tur_rol = self._aday_skor_hesapla(aday_rol, uzanti)
                if skor_rol > en_iyi_skor:
                    en_iyi_skor = skor_rol
                    en_iyi_tur = tur_rol
                    en_iyi_algoritma_adi = f"Dinamik-BitRotasyon-ROL({shift})"
                    en_iyi_cozum_baytlari = bytes(self._rol8(b, shift) for b in ham_veri)
                    if skor_rol >= 95.0:
                        break

                # yarım bayt değişimi ve xor.
                aday_nib = bytes(self._nibble_swap(b) for b in ilk_parca)
                skor_nib, tur_nib = self._aday_skor_hesapla(aday_nib, uzanti)
                if skor_nib > en_iyi_skor:
                    en_iyi_skor = skor_nib
                    en_iyi_tur = tur_nib
                    en_iyi_algoritma_adi = "Dinamik-Nibble-Swap"
                    en_iyi_cozum_baytlari = bytes(self._nibble_swap(b) for b in ham_veri)

        # aday 4: dinamik anahtar akışı sentezi.
        if en_iyi_skor < 95.0:
            cubuk.guncelle(90 if harici_cubuk else 65, asama="Dinamik PRNG Keystream ve Akış Üreteci taranıyor")
            dengeli_bekle(0.06)

            lcg_carpanlar = [1103515245, 1664525, 214013, 69069, 134775813]
            for carpan in lcg_carpanlar:
                for tohum in (0, 1, 42, 1234, 0x1337, len(ham_veri) & 0xFFFF):
                    state = tohum
                    c_akis = bytearray()
                    for _ in range(len(ilk_parca)):
                        state = (carpan * state + 12345) & 0xFFFFFFFF
                        c_akis.append((state >> 16) & 0xFF)
                    
                    aday_lcg = bytes(b ^ k for b, k in zip(ilk_parca, c_akis))
                    skor_lcg, tur_lcg = self._aday_skor_hesapla(aday_lcg, uzanti)
                    if skor_lcg > en_iyi_skor:
                        en_iyi_skor = skor_lcg
                        en_iyi_tur = tur_lcg
                        en_iyi_algoritma_adi = f"Dinamik-LCG-Keystream(Multiplier=0x{carpan:X}, Seed={tohum})"
                        tam_state = tohum
                        tam_cozum = bytearray(toplam_boyut)
                        for idx, b in enumerate(ham_veri):
                            tam_state = (carpan * tam_state + 12345) & 0xFFFFFFFF
                            tam_cozum[idx] = b ^ ((tam_state >> 16) & 0xFF)
                        en_iyi_cozum_baytlari = bytes(tam_cozum)
                        if skor_lcg >= 95.0:
                            break
                if en_iyi_skor >= 95.0:
                    break

        cubuk.guncelle(97 if harici_cubuk else 95, asama="Kurtarma doğrulaması ve çıktı hazırlanıyor")
        dengeli_bekle(0.06)

        # aday yapısal olarak doğrulanırsa başarılı sayar.
        if en_iyi_cozum_baytlari and en_iyi_skor >= 65.0 and en_iyi_tur:
            hedef_dizin = self.hedef_cikti_dizini or os.path.dirname(dosya_yolu)
            os.makedirs(hedef_dizin, exist_ok=True)
            cikti_yolu = os.path.join(hedef_dizin, dosya_adi + ".kurtarildi")

            if not self.kuru_calistirma:
                if self.yedek_al and not os.path.exists(dosya_yolu + ".bak"):
                    shutil.copy2(dosya_yolu, dosya_yolu + ".bak")
                with open(cikti_yolu, "wb") as out_f:
                    out_f.write(en_iyi_cozum_baytlari)

            if not harici_cubuk:
                cubuk.animasyonlu_tamamla(
                    hedef_dosya=cikti_yolu,
                    basarili=True,
                    detay=f"{en_iyi_algoritma_adi} -> {en_iyi_tur}"
                )

            return {
                "basarili": True,
                "dosya": dosya_yolu,
                "cikti": cikti_yolu,
                "sentezlenen_algoritma": en_iyi_algoritma_adi,
                "dogrulanan_tur": en_iyi_tur,
                "guven_skoru": en_iyi_skor,
                "kuru_calistirma": self.kuru_calistirma
            }
        else:
            if not harici_cubuk:
                cubuk.animasyonlu_tamamla(hedef_dosya=dosya_yolu, basarili=False)
            return {
                "basarili": False,
                "dosya": dosya_yolu,
                "hata": "Otonom algoritma sentezleyici geçerli ve sağlam bir format üretemedi"
            }
