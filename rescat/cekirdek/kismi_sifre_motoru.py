import os
import shutil
from typing import Dict, Any, Optional, Callable, List, Tuple
from rescat.cekirdek.dosya_tanimlayici import sihirli_baytlardan_tur_tahmin_et


class KismiSifreMotoru:
    """
    modern kurumsal fidye yazılımlarının (lockbit 3.0, blackcat, play, vice society)
    hızlı işlem yapmak için kullandığı kısmi (ıntermittent / spot / stride / header-only)
    şifreleme modellerini çözen hibrit rekonstrüksiyon motoru.
    """

    def __init__(self, kuru_calistirma: bool = False, yedek_al: bool = True) -> None:
        self.kuru_calistirma: bool = kuru_calistirma
        self.yedek_al: bool = yedek_al

    def baslik_coz(
        self,
        veri: bytes,
        blok_boyutu: int,
        cozucu_fonk: Callable[[bytes], bytes]
    ) -> bytes:
        """
        dosyanın yalnızca ilk n baytı şifrelenmişse (header-only),
        ilk bloğu çözüp sağlam gövde ile birleştirir.
        """
        toplam = len(veri)
        if toplam <= blok_boyutu:
            return cozucu_fonk(veri)

        sifreli_baslik = veri[:blok_boyutu]
        kalan_govde = veri[blok_boyutu:]
        cozulmus_baslik = cozucu_fonk(sifreli_baslik)
        return cozulmus_baslik + kalan_govde

    def adimli_coz(
        self,
        veri: bytes,
        sifreli_adim: int,
        atlama_adimi: int,
        cozucu_fonk: Callable[[bytes], bytes]
    ) -> bytes:
        """
        adımlı (stride / pattern) şifreleme:
        her `atlama_adimi` baytta bir `sifreli_adim` bayt şifrelenmişse,
        yalnızca ilgili sektörleri çözüp orijinal konumlara yazar.
        """
        toplam = len(veri)
        cikti = bytearray()
        ofset = 0

        while ofset < toplam:
            kalan = toplam - ofset
            bu_adim_boyutu = min(sifreli_adim, kalan)

            # şifreli bloğu çözer.
            sifreli_parca = veri[ofset:ofset + bu_adim_boyutu]
            try:
                cozulmus_parca = cozucu_fonk(sifreli_parca)
                cikti.extend(cozulmus_parca)
            except Exception:
                cikti.extend(sifreli_parca)

            ofset += bu_adim_boyutu

            # sağlam bloğu doğrudan kopyalar.
            if ofset < toplam and atlama_adimi > 0:
                bu_atlama = min(atlama_adimi, toplam - ofset)
                cikti.extend(veri[ofset:ofset + bu_atlama])
                ofset += bu_atlama

        return bytes(cikti)

    @staticmethod
    def periyodik_adim_profili_cikar(veri: bytes, blok_boyutu: int = 4096) -> Dict[str, Any]:
        """
        kayan pencere entropisi ve bayt varyansı üzerinden dosyadaki periyodik
        şifreli (yüksek entropi) ve sağlam (düşük/normal entropi) blok boyutlarını hesaplar.
        """
        from rescat.cekirdek.entropi import shannon_entropisi_hesapla

        toplam = len(veri)
        if toplam < blok_boyutu * 2:
            return {"tespit_edildi": False, "sifreli_adim": toplam, "atlama_adimi": 0}

        blok_durumlari: List[bool] = []  # entropi eşiğine göre şifreli veya düz metin ayrımı.
        for ofset in range(0, toplam, blok_boyutu):
            parca = veri[ofset:ofset + blok_boyutu]
            ent = shannon_entropisi_hesapla(parca)
            blok_durumlari.append(ent >= 7.20)

        # durum geçişlerini analiz eder.
        runs: List[Tuple[bool, int]] = []
        if blok_durumlari:
            suanki_durum = blok_durumlari[0]
            suanki_uzunluk = 1
            for d in blok_durumlari[1:]:
                if d == suanki_durum:
                    suanki_uzunluk += 1
                else:
                    runs.append((suanki_durum, suanki_uzunluk * blok_boyutu))
                    suanki_durum = d
                    suanki_uzunluk = 1
            runs.append((suanki_durum, suanki_uzunluk * blok_boyutu))

        sifreli_kosular = [uz for durum, uz in runs if durum]
        duz_kosular = [uz for durum, uz in runs if not durum]

        if sifreli_kosular and duz_kosular:
            from collections import Counter
            en_sik_sifreli = Counter(sifreli_kosular).most_common(1)[0][0]
            en_sik_duz = Counter(duz_kosular).most_common(1)[0][0]
            return {
                "tespit_edildi": True,
                "sifreli_adim": en_sik_sifreli,
                "atlama_adimi": en_sik_duz,
                "kosu_sayisi": len(runs)
            }

        return {"tespit_edildi": False, "sifreli_adim": toplam, "atlama_adimi": 0}

    def otomatik_kismi_kurtar(
        self,
        dosya_yolu: str,
        cozucu_fonk: Callable[[bytes], bytes],
        hedef_cikti: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        dosya üzerinde dinamik profil ve standart intermittent modellerini (1mb header, 150kb, 64kb stride vb.)
        deneyerek sihirli bayt doğrulamasıyla en başarılı sonucu tespit eder.
        """
        if not os.path.exists(dosya_yolu):
            return {"basarili": False, "hata": "Dosya bulunamadi"}

        try:
            with open(dosya_yolu, "rb") as f:
                ham_veri = f.read()

            toplam_boyut = len(ham_veri)
            if toplam_boyut == 0:
                return {"basarili": False, "hata": "Dosya boş"}

            # dinamik profil analizi yapar.
            profil = self.periyodik_adim_profili_cikar(ham_veri)

            # aday modeller.
            modeller = [
                ("Tam Şifreleme", lambda d: cozucu_fonk(d)),
                ("Header-150KB (STOP/Djvu)", lambda d: self.baslik_coz(d, min(153600, toplam_boyut), cozucu_fonk)),
                ("Header-1MB (BlackCat/LockBit)", lambda d: self.baslik_coz(d, min(1048576, toplam_boyut), cozucu_fonk)),
                ("Header-4KB (SQLite Page 1)", lambda d: self.baslik_coz(d, min(4096, toplam_boyut), cozucu_fonk)),
                ("Stride-1MB/1MB (Intermittent)", lambda d: self.adimli_coz(d, 1048576, 1048576, cozucu_fonk)),
                ("Stride-64KB/64KB", lambda d: self.adimli_coz(d, 65536, 65536, cozucu_fonk)),
            ]

            if profil.get("tespit_edildi"):
                s_adim = profil["sifreli_adim"]
                a_adim = profil["atlama_adimi"]
                modeller.insert(0, (f"Dinamik-Stride-{s_adim//1024}KB/{a_adim//1024}KB", lambda d: self.adimli_coz(d, s_adim, a_adim, cozucu_fonk)))

            en_iyi_sonuc: Optional[bytes] = None
            en_iyi_model_adi: str = ""
            en_iyi_tur: Optional[str] = None

            for model_adi, model_fn in modeller:
                try:
                    aday_cozum = model_fn(ham_veri)
                    tur = sihirli_baytlardan_tur_tahmin_et(aday_cozum[:64])
                    if tur:
                        en_iyi_sonuc = aday_cozum
                        en_iyi_model_adi = model_adi
                        en_iyi_tur = tur
                        break
                except Exception:
                    continue

            # sihirli bayt bulunamazsa tam şifreleme modeli denenir.
            if en_iyi_sonuc is None:
                try:
                    en_iyi_sonuc = cozucu_fonk(ham_veri)
                    en_iyi_model_adi = "Tam Şifreleme (Fallback)"
                    en_iyi_tur = sihirli_baytlardan_tur_tahmin_et(en_iyi_sonuc[:64])
                except Exception as e:
                    return {"basarili": False, "hata": f"Çözücü fonksiyon hatası: {e}"}

            cikti_yolu = hedef_cikti or (dosya_yolu + ".cozuldu")
            if not self.kuru_calistirma:
                if self.yedek_al and not os.path.exists(dosya_yolu + ".bak"):
                    shutil.copy2(dosya_yolu, dosya_yolu + ".bak")

                with open(cikti_yolu, "wb") as out_f:
                    out_f.write(en_iyi_sonuc)

            return {
                "basarili": True,
                "dosya": dosya_yolu,
                "cikti": cikti_yolu,
                "uygulanan_model": en_iyi_model_adi,
                "dogrulanan_tur": en_iyi_tur,
                "toplam_boyut": toplam_boyut,
                "kuru_calistirma": self.kuru_calistirma
            }

        except Exception as e:
            return {"basarili": False, "hata": str(e)}
