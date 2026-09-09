import os
import sys
import glob
from typing import Dict, List, Optional, Any, Tuple
from rescat.yardimcilar.konsol import (
    banner_yazdir,
    bilgi_yaz,
    basari_yaz,
    uyari_yaz,
    hata_yaz,
    kritik_yaz,
    baslik_yaz,
    tablo_satiri_yaz,
    masaustu_dizini_al,
    dengeli_bekle,
    YuklenmeCubugu
)
from rescat.yardimcilar.raporlayici import Raporlayici
from rescat.cekirdek.entropi import dosya_entropisi_hesapla, kayan_pencere_entropisi
from rescat.cekirdek.dosya_tanimlayici import dosya_baslik_analizi_yap, sihirli_baytlardan_tur_tahmin_et
from rescat.cekirdek.baslik_onarici import baslik_yama
from rescat.cekirdek.djvu_veritabani import uzantiya_gore_offline_anahtar_al
from rescat.analizciler.bellek_anahtar_avcisi import bellek_dosyasini_tara
from rescat.cozuculer.djvu_cozucu import DjvuCozucu
from rescat.cozuculer.aes_cozucu import AesCozucu
from rescat.cozuculer.xor_cozucu import XorCozucu
from rescat.cozuculer.chacha_cozucu import ChaChaCozucu
from rescat.cozuculer.poly1305_cozucu import Poly1305Cozucu
from rescat.cozuculer.evrensel_cozucu import CozucuFabrikasi
from rescat.cozuculer.office_cozucu import OfficeCozucu
from rescat.cekirdek.yapisal_kurtarici import YapisalKurtarmaMotoru
from rescat.cekirdek.keystream_cozucu import KeystreamCozucu
from rescat.cekirdek.kismi_sifre_motoru import KismiSifreMotoru
from rescat.analizciler.footer_ayristirici import FooterAyristirici
from rescat.cekirdek.sizinti_veritabani import (
    sizinti_anahtari_sorgula,
    bilinen_cozucu_tavsiyesi,
    DJVU_GENISLETILMIS_OFFLINE_ANAHTARLAR
)


from rescat.cekirdek.zaman_kirici import dosya_zaman_damgasi_al, zaman_tabanli_xor_kir
from rescat.cekirdek.entropi import dosya_entropisi_hesapla, kayan_pencere_entropisi, kismi_sifreleme_analizi
from rescat.cekirdek.algoritma_tespit import algoritma_tespit_et
from rescat.cekirdek.bilinen_metin import bilinen_metin_saldirisi_yap
from rescat.cekirdek.dosya_tanimlayici import BILINEN_SIHIRLI_BAYTLAR
from rescat.cekirdek.otonom_algoritma_uretici import OtonomAlgoritmaUretici
from rescat.cekirdek.lokal_ai_motoru import LokalYapayZekaMotoru


class OtonomKurtarmaMotoru:
    # tam otonom adli analiz ve kurtarma motoru.
    def __init__(
        self,
        hedef: Optional[str] = None,
        hedef_dizin: Optional[str] = None,
        cikti_dizini: Optional[str] = None,
        kuru_calistirma: bool = False,
        yedek_al: bool = True,
        uzanti_filtresi: Optional[str] = None,
        tekil_dosya: Optional[str] = None,
        rapor_diske_kaydet: bool = False,
        interaktif_sor: bool = False,
        ek_sozluk_kelimeleri: Optional[List[str]] = None
    ) -> None:
        self.interaktif_sor: bool = interaktif_sor
        self.ek_sozluk_kelimeleri: List[str] = ek_sozluk_kelimeleri or []
        hedef_yol = tekil_dosya or hedef or hedef_dizin or os.getcwd()
        hedef_yol = os.path.abspath(hedef_yol)

        if os.path.isfile(hedef_yol):
            self.tekil_dosya: Optional[str] = hedef_yol
            self.hedef_dizin: str = os.path.dirname(hedef_yol)
            vaka_adi = f"ozel_{os.path.basename(hedef_yol)}"
        else:
            self.tekil_dosya = None
            self.hedef_dizin = hedef_yol
            vaka_adi = f"otonom_{os.path.basename(self.hedef_dizin)}"

        self.uzanti_filtresi: Optional[str] = uzanti_filtresi.lower() if uzanti_filtresi else None
        if self.uzanti_filtresi and not self.uzanti_filtresi.startswith("."):
            self.uzanti_filtresi = "." + self.uzanti_filtresi

        self.cikti_dizini: str = os.path.abspath(cikti_dizini or masaustu_dizini_al())
        self.kuru_calistirma: bool = kuru_calistirma
        self.yedek_al: bool = yedek_al
        self.rapor_diske_kaydet: bool = rapor_diske_kaydet
        self.rapor: Raporlayici = Raporlayici(vaka_adi=vaka_adi)

        self.bellek_dokumleri: List[str] = []
        self.sifreli_dosyalar: List[str] = []
        self.kurtarilan_anahtarlar: List[Dict[str, Any]] = []
        self.cozulen_dosyalar: List[Dict[str, Any]] = []

    def dosyalari_kesfet(self) -> None:
        # hedefi tarayarak bellek dökümlerini ve şifreli dosyaları tespit eder.
        bilnen_bellek_uzantilari = (".dmp", ".dump", ".raw", ".vmem", ".mem", ".bin")
        bilinen_zararli_uzantilari = (
            ".djvu", ".stop", ".locked", ".crypto", ".lockbit", ".conti",
            ".crypted", ".enc", ".wncry", ".wcry", ".gero", ".coot", ".derp",
            ".nbes", ".rumba", ".karl", ".zida"
        )

        if self.tekil_dosya:
            if os.path.exists(self.tekil_dosya):
                uz = os.path.splitext(self.tekil_dosya.lower())[1]
                if uz in bilnen_bellek_uzantilari and os.path.getsize(self.tekil_dosya) > 1024:
                    self.bellek_dokumleri.append(self.tekil_dosya)
                else:
                    self.sifreli_dosyalar.append(self.tekil_dosya)

            if os.path.exists(self.hedef_dizin):
                try:
                    for d in os.listdir(self.hedef_dizin):
                        tam_yol = os.path.join(self.hedef_dizin, d)
                        if os.path.isfile(tam_yol):
                            uz = os.path.splitext(d.lower())[1]
                            if uz in bilnen_bellek_uzantilari and os.path.getsize(tam_yol) > 1024:
                                if tam_yol not in self.bellek_dokumleri:
                                    self.bellek_dokumleri.append(tam_yol)
                except Exception:
                    pass
        else:
            for kok_dizin, alt_dizinler, dosyalar in os.walk(self.hedef_dizin):
                if any(kara_dizin in kok_dizin for kara_dizin in [".git", "__pycache__", ".venv", "venv"]):
                    continue

                for dosya_adi in dosyalar:
                    if dosya_adi.endswith(".bak") or dosya_adi.startswith("kurtarma_raporu"):
                        continue

                    tam_yol = os.path.join(kok_dizin, dosya_adi)
                    kucuk_ad = dosya_adi.lower()
                    uzanti = os.path.splitext(kucuk_ad)[1]

                    if uzanti in bilnen_bellek_uzantilari and os.path.getsize(tam_yol) > 1024:
                        self.bellek_dokumleri.append(tam_yol)
                        continue

                    if self.uzanti_filtresi:
                        if uzanti == self.uzanti_filtresi:
                            self.sifreli_dosyalar.append(tam_yol)
                        continue

                    if uzanti in bilinen_zararli_uzantilari:
                        self.sifreli_dosyalar.append(tam_yol)
                        continue

                    try:
                        boyut = os.path.getsize(tam_yol)
                        if 16 <= boyut <= 500 * 1024 * 1024:
                            entropi = dosya_entropisi_hesapla(tam_yol)
                            if entropi >= 7.2:
                                self.sifreli_dosyalar.append(tam_yol)
                            else:
                                tespit = algoritma_tespit_et(tam_yol)
                                if tespit.get("sifreli_mi") and tespit.get("kategori") != "SIFRESIZ":
                                    self.sifreli_dosyalar.append(tam_yol)
                    except Exception:
                        pass

    def bellek_anahtarlarini_avla(self) -> None:
        if not self.bellek_dokumleri:
            return

        for dokum_yolu in self.bellek_dokumleri:
            try:
                sonuclar = bellek_dosyasini_tara(dokum_yolu)
                aes256_listesi = sonuclar.get("dogrulanmis_aes256_anahtarlari", [])
                aes128_listesi = sonuclar.get("dogrulanmis_aes128_anahtarlari", [])
                olasi_adaylar = sonuclar.get("olasi_aes_anahtar_adaylari", [])

                for ch in sonuclar.get("chacha20_anahtarlari", []):
                    kayit = {
                        "tur": "ChaCha20",
                        "deger": ch["anahtar_hex"],
                        "nonce": ch.get("nonce_ietf_hex", ""),
                        "sayac_ve_nonce": ch.get("sayac_ve_nonce_hex", ""),
                        "kaynak": f"Bellek ChaCha20 Durum Matrisi (Ofset {ch['ofset']}): {os.path.basename(dokum_yolu)}"
                    }
                    self.kurtarilan_anahtarlar.append(kayit)
                    self.rapor.anahtar_ekle(kayit)

                for sal in sonuclar.get("salsa20_anahtarlari", []):
                    kayit = {
                        "tur": "Salsa20",
                        "deger": sal["anahtar_hex"],
                        "nonce": sal.get("nonce_hex", ""),
                        "kaynak": f"Bellek Salsa20 Durum Matrisi: {os.path.basename(dokum_yolu)}"
                    }
                    self.kurtarilan_anahtarlar.append(kayit)
                    self.rapor.anahtar_ekle(kayit)

                for tea in sonuclar.get("tea_anahtarlari", []):
                    kayit = {
                        "tur": "TEA-XTEA",
                        "deger": tea["anahtar_hex"],
                        "kaynak": f"Bellek TEA Delta: {os.path.basename(dokum_yolu)}"
                    }
                    self.kurtarilan_anahtarlar.append(kayit)

                for xk in sonuclar.get("x25519_anahtarlari", []):
                    kayit = {
                        "tur": "Curve25519",
                        "deger": xk["ozel_anahtar_hex"],
                        "kamu": xk.get("kamu_anahtar_hex", ""),
                        "kaynak": f"Bellek Curve25519 (RFC 7748 Clamped): {os.path.basename(dokum_yolu)}"
                    }
                    self.kurtarilan_anahtarlar.append(kayit)
                    self.rapor.anahtar_ekle(kayit)

                for rsa_pem in sonuclar.get("rsa_ozel_anahtarlari", []):
                    kayit = {
                        "tur": "RSA-Private",
                        "deger": rsa_pem,
                        "kaynak": f"Bellek RSA Private Key (ASN.1 DER/PEM): {os.path.basename(dokum_yolu)}"
                    }
                    self.kurtarilan_anahtarlar.append(kayit)
                    self.rapor.anahtar_ekle(kayit)

                for anahtar_hex in aes256_listesi:
                    kayit = {
                        "tur": "AES-256",
                        "deger": anahtar_hex,
                        "kaynak": f"Bellek Key Schedule (AES-256): {os.path.basename(dokum_yolu)}"
                    }
                    if not any(k["deger"] == anahtar_hex for k in self.kurtarilan_anahtarlar):
                        self.kurtarilan_anahtarlar.append(kayit)

                for anahtar_hex in aes128_listesi:
                    kayit = {
                        "tur": "AES-128",
                        "deger": anahtar_hex,
                        "kaynak": f"Bellek Key Schedule (AES-128): {os.path.basename(dokum_yolu)}"
                    }
                    if not any(k["deger"] == anahtar_hex for k in self.kurtarilan_anahtarlar):
                        self.kurtarilan_anahtarlar.append(kayit)

                for a in olasi_adaylar:
                    kayit = {
                        "tur": "AES-192-Aday",
                        "deger": a,
                        "kaynak": f"Bellek 192-bit: {os.path.basename(dokum_yolu)}"
                    }
                    if not any(k["deger"] == a for k in self.kurtarilan_anahtarlar):
                        self.kurtarilan_anahtarlar.append(kayit)

                with open(dokum_yolu, "rb") as bf:
                    ham_b = bf.read(10 * 1024 * 1024)
                    adim_boyutu = 1 if len(ham_b) <= 64 * 1024 else 16
                    sinir = len(ham_b) - 32
                    for ofset in range(0, sinir, adim_boyutu):
                        blok = ham_b[ofset:ofset + 32]
                        if len(set(blok)) >= 14:
                            hex_b = blok.hex()
                            if not any(k["deger"] == hex_b for k in self.kurtarilan_anahtarlar):
                                self.kurtarilan_anahtarlar.append({
                                    "tur": "AES-256-Ham",
                                    "deger": hex_b,
                                    "kaynak": f"Ham Bellek: {os.path.basename(dokum_yolu)}"
                                })
            except Exception:
                pass

    def dosyalari_otonom_coz(self) -> None:
        if not self.sifreli_dosyalar:
            return

        stop_uzantilari = tuple(f".{u}" for u in DJVU_GENISLETILMIS_OFFLINE_ANAHTARLAR.keys())

        for dosya_yolu in self.sifreli_dosyalar:
            dosya_adi = os.path.basename(dosya_yolu)
            uzanti = os.path.splitext(dosya_yolu)[1].lower()
            cozum_basarili = False

            cubuk = YuklenmeCubugu(toplam=100, baslik="Şifre Çözülüyor", dosya_adi=dosya_adi)
            cubuk.guncelle(10, asama="Entropi ve bayt analizi")
            dengeli_bekle(0.06)

            algoritma_bilgisi = algoritma_tespit_et(dosya_yolu)
            algo_adi = algoritma_bilgisi.get("algoritma", "Bilinmeyen Algoritma")
            cubuk.guncelle(25, asama=f"Kripto analizi ({algo_adi[:16]})")
            dengeli_bekle(0.06)

            if uzanti in stop_uzantilari or uzanti in (".djvu", ".stop") or "Stop/Djvu" in algo_adi:
                cubuk.guncelle(40, asama="Offline anahtar veritabanı")
                dengeli_bekle(0.05)
                test_cozucu = DjvuCozucu(kuru_calistirma=True)
                test_sonuc = test_cozucu.tekil_dosya_coz(dosya_yolu, animasyon=False)
                if test_sonuc.get("basarili") and (test_sonuc.get("dogrulanan_tur") or test_sonuc.get("kurban_id")):
                    djvu_cozucu = DjvuCozucu(
                        kuru_calistirma=self.kuru_calistirma,
                        yedek_al=self.yedek_al,
                        hedef_cikti_dizini=self.cikti_dizini
                    )
                    sonuc = djvu_cozucu.tekil_dosya_coz(dosya_yolu, animasyon=False)
                    cozum_basarili = True
                    self.cozulen_dosyalar.append(sonuc)
                    self.rapor.cozum_ekle({
                        "dosya_yolu": dosya_yolu,
                        "basarili": True,
                        "algoritma": "Stop/Djvu AES-256 (Expanded Offline Key)",
                        "dogrulanan_tur": sonuc.get("dogrulanan_tur")
                    })
                    cubuk.animasyonlu_tamamla(
                        hedef_dosya=sonuc.get("hedef_yol") or dosya_adi,
                        basarili=True,
                        detay=f"Stop/Djvu AES-256 -> {sonuc.get('dogrulanan_tur') or 'Bilinmiyor'}"
                    )
                    continue

            # 1.5 aşama: şifreli microsoft office belgesi çözümü.
            if not cozum_basarili:
                try:
                    with open(dosya_yolu, "rb") as f_on:
                        sifreli_on_baytlar = f_on.read(4096)
                except Exception:
                    sifreli_on_baytlar = b""

                if OfficeCozucu.office_belgesi_mi(sifreli_on_baytlar):
                    cubuk.guncelle(45, asama="Şifreli Office Dokümanı Çözülüyor")
                    dengeli_bekle(0.05)
                    aday_parolalar = ["VelvetSweatshop", "", "123456", "password", "1234", "admin", "12345678", "root", "excel", "test"]
                    for k in self.kurtarilan_anahtarlar:
                        if k.get("deger"):
                            aday_parolalar.append(k["deger"])

                    off_cozucu = OfficeCozucu(
                        parolalar=aday_parolalar,
                        kuru_calistirma=self.kuru_calistirma,
                        yedek_al=self.yedek_al,
                        hedef_cikti_dizini=self.cikti_dizini
                    )
                    sonuc = off_cozucu.tekil_dosya_coz(dosya_yolu, animasyon=False)
                    if sonuc.get("basarili") and sonuc.get("dogrulanan_tur"):
                        cozum_basarili = True
                        self.cozulen_dosyalar.append(sonuc)
                        self.rapor.cozum_ekle({
                            "dosya_yolu": dosya_yolu,
                            "basarili": True,
                            "algoritma": "MS-Office Agile/Standard AES Decryption",
                            "dogrulanan_tur": sonuc.get("dogrulanan_tur")
                        })
                        cubuk.animasyonlu_tamamla(
                            hedef_dosya=sonuc.get("hedef_yol") or dosya_adi,
                            basarili=True,
                            detay=f"MS-Office AES -> {sonuc.get('dogrulanan_tur') or 'xlsx/docx'}"
                        )
                        continue

            # 1.6 aşama: openssl salted şifreli dosya çözümü.
            if not cozum_basarili:
                try:
                    with open(dosya_yolu, "rb") as f_on:
                        sifreli_on_baytlar = f_on.read(4096)
                except Exception:
                    sifreli_on_baytlar = b""

                if sifreli_on_baytlar.startswith(b"Salted__"):
                    from rescat.cozuculer.openssl_cozucu import OpenSslCozucu
                    cubuk.guncelle(48, asama="OpenSSL Salted şifre çözümü")
                    dengeli_bekle(0.05)

                    aday_parolalar = [
                        "password", "123456", "1234", "12345", "admin", "root",
                        "sifre", "deneme", "rescat", "qwerty", "test", "test123",
                        "eren", "erensogutlu", "pc", "parola", "crypto", "secret",
                        "12345678", "123456789", "toor", "kali", "asdfgh"
                    ]
                    for ek in self.ek_sozluk_kelimeleri:
                        if ek and ek not in aday_parolalar:
                            aday_parolalar.append(ek)
                    kok_ad = os.path.splitext(dosya_adi)[0]
                    for parca in kok_ad.replace("-", "_").split("."):
                        if parca and parca not in aday_parolalar:
                            aday_parolalar.append(parca)
                            aday_parolalar.append(parca + "123")
                            aday_parolalar.append(parca + "1")

                    for k in self.kurtarilan_anahtarlar:
                        deg = k.get("deger", "")
                        if deg and deg not in aday_parolalar:
                            aday_parolalar.append(deg)

                    # çok çekirdekli paralel kırma ve kural tabanlı mutasyon.
                    try:
                        with open(dosya_yolu, "rb") as f_tam:
                            tam_baytlar = f_tam.read()
                        from rescat.cekirdek.parola_mutasyon import (
                            kural_tabanli_mutasyon,
                            sistem_sozluklerini_tara,
                            ParalelKiriciMotor
                        )
                        genisletilmis = kural_tabanli_mutasyon(aday_parolalar, max_toplam=300)
                        genisletilmis.extend(sistem_sozluklerini_tara(max_kelime=500))
                        kirici = ParalelKiriciMotor()
                        paralel_res = kirici.openssl_paralel_kir(tam_baytlar, genisletilmis)
                        if paralel_res:
                            kazanan_parola, kazanan_algo, cozulen_b = paralel_res
                            gercek_op = OpenSslCozucu(
                                parola_veya_anahtar=kazanan_parola.encode("utf-8", errors="ignore"),
                                algoritma_adi=kazanan_algo,
                                kuru_calistirma=self.kuru_calistirma,
                                yedek_al=self.yedek_al,
                                hedef_cikti_dizini=self.cikti_dizini
                            )
                            sonuc = gercek_op.tekil_dosya_coz(dosya_yolu, animasyon=False)
                            cozum_basarili = True
                            self.cozulen_dosyalar.append(sonuc)
                            self.rapor.cozum_ekle({
                                "dosya_yolu": dosya_yolu,
                                "basarili": True,
                                "algoritma": f"OpenSSL {kazanan_algo.upper()}",
                                "parola": kazanan_parola,
                                "dogrulanan_tur": sonuc.get("dogrulanan_tur")
                            })
                            cubuk.animasyonlu_tamamla(
                                hedef_dosya=sonuc.get("hedef_yol") or dosya_adi,
                                basarili=True,
                                detay=f"OpenSSL {kazanan_algo.upper()} (Çok Çekirdekli Parola: {kazanan_parola}) -> {sonuc.get('dogrulanan_tur')}"
                            )
                    except Exception:
                        pass

                    if not cozum_basarili:
                        for parola_aday in aday_parolalar:
                            for algo in ("aes-256-cbc", "aes-128-cbc"):
                                test_op = OpenSslCozucu(
                                    parola_veya_anahtar=parola_aday.encode("utf-8", errors="ignore"),
                                    algoritma_adi=algo,
                                    kuru_calistirma=True
                                )
                                test_sonuc = test_op.tekil_dosya_coz(dosya_yolu, animasyon=False)
                                if test_sonuc.get("basarili") and test_sonuc.get("dogrulanan_tur"):
                                    gercek_op = OpenSslCozucu(
                                        parola_veya_anahtar=parola_aday.encode("utf-8", errors="ignore"),
                                        algoritma_adi=algo,
                                        kuru_calistirma=self.kuru_calistirma,
                                        yedek_al=self.yedek_al,
                                        hedef_cikti_dizini=self.cikti_dizini
                                    )
                                    sonuc = gercek_op.tekil_dosya_coz(dosya_yolu, animasyon=False)
                                    cozum_basarili = True
                                    self.cozulen_dosyalar.append(sonuc)
                                    self.rapor.cozum_ekle({
                                        "dosya_yolu": dosya_yolu,
                                        "basarili": True,
                                        "algoritma": f"OpenSSL {algo.upper()}",
                                        "parola": parola_aday,
                                        "dogrulanan_tur": sonuc.get("dogrulanan_tur")
                                    })
                                    cubuk.animasyonlu_tamamla(
                                        hedef_dosya=sonuc.get("hedef_yol") or dosya_adi,
                                        basarili=True,
                                        detay=f"OpenSSL {algo.upper()} (Parola: {parola_aday}) -> {sonuc.get('dogrulanan_tur')}"
                                    )
                                    break
                            if cozum_basarili:
                                break

            if not cozum_basarili and self.kurtarilan_anahtarlar:
                cubuk.guncelle(55, asama="Bellek & evrensel kripto taraması")
                dengeli_bekle(0.05)
                try:
                    with open(dosya_yolu, "rb") as f_on:
                        sifreli_on_baytlar = f_on.read(4096)
                except Exception:
                    sifreli_on_baytlar = b""

                for anahtar_kaydi in self.kurtarilan_anahtarlar:
                    tur = anahtar_kaydi.get("tur", "")
                    deger_hex = anahtar_kaydi.get("deger", "")
                    if not deger_hex:
                        continue

                    try:
                        anahtar_baytlari = bytes.fromhex(deger_hex)
                    except Exception:
                        continue

                    if sifreli_on_baytlar:
                        if "AES" in tur:
                            hedef_algolar = ["aes"]
                        elif "ChaCha" in tur:
                            hedef_algolar = ["chacha20", "poly1305"]
                        elif "Salsa" in tur:
                            hedef_algolar = ["salsa20"]
                        elif "TEA" in tur:
                            hedef_algolar = ["tea", "xtea", "xxtea"]
                        else:
                            hedef_algolar = ["aes", "chacha20", "rc4", "twofish"]

                        oto_deneme = CozucuFabrikasi.aday_anahtarla_otomatik_dene(
                            sifreli_on_baytlar,
                            anahtar_baytlari,
                            aday_algoritmalar=hedef_algolar
                        )
                        if oto_deneme and oto_deneme.get("basarili"):
                            secilen_cozucu = oto_deneme["cozucu"]
                            secilen_cozucu.kuru_calistirma = self.kuru_calistirma
                            secilen_cozucu.yedek_al = self.yedek_al
                            secilen_cozucu.hedef_cikti_dizini = self.cikti_dizini
                            sonuc = secilen_cozucu.tekil_dosya_coz(dosya_yolu, animasyon=False)

                            if not (sonuc.get("basarili") and sonuc.get("dogrulanan_tur")):
                                kismi_motor = KismiSifreMotoru(kuru_calistirma=self.kuru_calistirma, yedek_al=self.yedek_al)
                                kismi_sonuc = kismi_motor.otomatik_kismi_kurtar(dosya_yolu, secilen_cozucu.baytlari_coz)
                                if kismi_sonuc.get("basarili") and kismi_sonuc.get("dogrulanan_tur"):
                                    sonuc = kismi_sonuc

                            if sonuc.get("basarili") and sonuc.get("dogrulanan_tur"):
                                cozum_basarili = True
                                self.cozulen_dosyalar.append(sonuc)
                                self.rapor.cozum_ekle({
                                    "dosya_yolu": dosya_yolu,
                                    "basarili": True,
                                    "algoritma": oto_deneme["algoritma"],
                                    "dogrulanan_tur": sonuc.get("dogrulanan_tur")
                                })
                                cubuk.animasyonlu_tamamla(
                                    hedef_dosya=sonuc.get("hedef_yol") or dosya_adi,
                                    basarili=True,
                                    detay=f"{oto_deneme['algoritma']} -> {sonuc.get('dogrulanan_tur')}"
                                )
                                break

                    if not cozum_basarili and tur == "ChaCha20":
                        try:
                            nonce_hex = anahtar_kaydi.get("sayac_ve_nonce") or anahtar_kaydi.get("nonce", "00" * 16)
                            nonce_baytlari = bytes.fromhex(nonce_hex) if nonce_hex else None
                            denenecek_nonceler = [None, nonce_baytlari] if nonce_baytlari else [None]
                            for n_aday in denenecek_nonceler:
                                test_chacha = ChaChaCozucu(
                                    anahtar_baytlari=anahtar_baytlari,
                                    guvenlik_no=n_aday,
                                    nonce_dosya_basinda_mi=(n_aday is None),
                                    kuru_calistirma=True
                                )
                                test_sonuc = test_chacha.tekil_dosya_coz(dosya_yolu, animasyon=False)
                                if test_sonuc.get("basarili") and test_sonuc.get("dogrulanan_tur"):
                                    chacha_cozucu = ChaChaCozucu(
                                        anahtar_baytlari=anahtar_baytlari,
                                        guvenlik_no=n_aday,
                                        nonce_dosya_basinda_mi=(n_aday is None),
                                        kuru_calistirma=self.kuru_calistirma,
                                        yedek_al=self.yedek_al,
                                        hedef_cikti_dizini=self.cikti_dizini
                                    )
                                    sonuc = chacha_cozucu.tekil_dosya_coz(dosya_yolu, animasyon=False)
                                    cozum_basarili = True
                                    self.cozulen_dosyalar.append(sonuc)
                                    self.rapor.cozum_ekle({
                                        "dosya_yolu": dosya_yolu,
                                        "basarili": True,
                                        "algoritma": "ChaCha20-256",
                                        "dogrulanan_tur": sonuc.get("dogrulanan_tur")
                                    })
                                    cubuk.animasyonlu_tamamla(
                                        hedef_dosya=sonuc.get("hedef_yol") or dosya_adi,
                                        basarili=True,
                                        detay=f"ChaCha20-256 -> {sonuc.get('dogrulanan_tur')}"
                                    )
                                    break
                            if cozum_basarili:
                                break
                        except Exception:
                            pass

                    elif not cozum_basarili and ("Curve25519" in tur or "X25519" in tur):
                        try:
                            from rescat.cozuculer.x25519_cozucu import X25519HibritCozucu
                            for sim in ("chacha20", "aes-gcm", "aes-cbc"):
                                test_x = X25519HibritCozucu(
                                    ozel_anahtar_baytlari=anahtar_baytlari,
                                    simetrik_algoritma=sim,
                                    kuru_calistirma=True
                                )
                                test_sonuc = test_x.tekil_dosya_coz(dosya_yolu, animasyon=False)
                                if test_sonuc.get("basarili") and test_sonuc.get("dogrulanan_tur"):
                                    x_cozucu = X25519HibritCozucu(
                                        ozel_anahtar_baytlari=anahtar_baytlari,
                                        simetrik_algoritma=sim,
                                        kuru_calistirma=self.kuru_calistirma,
                                        yedek_al=self.yedek_al,
                                        hedef_cikti_dizini=self.cikti_dizini
                                    )
                                    sonuc = x_cozucu.tekil_dosya_coz(dosya_yolu, animasyon=False)
                                    cozum_basarili = True
                                    self.cozulen_dosyalar.append(sonuc)
                                    self.rapor.cozum_ekle({
                                        "dosya_yolu": dosya_yolu,
                                        "basarili": True,
                                        "algoritma": f"X25519-{sim.upper()}",
                                        "dogrulanan_tur": sonuc.get("dogrulanan_tur")
                                    })
                                    cubuk.animasyonlu_tamamla(
                                        hedef_dosya=sonuc.get("hedef_yol") or dosya_adi,
                                        basarili=True,
                                        detay=f"X25519-{sim.upper()} -> {sonuc.get('dogrulanan_tur')}"
                                    )
                                    break
                            if cozum_basarili:
                                break
                        except Exception:
                            pass

                    elif not cozum_basarili and "AES" in tur:
                        try:
                            for mod in ("cbc", "ctr", "ecb"):
                                test_aes = AesCozucu(
                                    anahtar_baytlari=anahtar_baytlari,
                                    mod_adi=mod,
                                    iv_dosya_basinda_mi=True,
                                    kuru_calistirma=True
                                )
                                test_sonuc = test_aes.tekil_dosya_coz(dosya_yolu, animasyon=False)
                                if test_sonuc.get("basarili") and test_sonuc.get("dogrulanan_tur"):
                                    aes_cozucu = AesCozucu(
                                        anahtar_baytlari=anahtar_baytlari,
                                        mod_adi=mod,
                                        iv_dosya_basinda_mi=True,
                                        kuru_calistirma=self.kuru_calistirma,
                                        yedek_al=self.yedek_al,
                                        hedef_cikti_dizini=self.cikti_dizini
                                    )
                                    sonuc = aes_cozucu.tekil_dosya_coz(dosya_yolu, animasyon=False)
                                    cozum_basarili = True
                                    self.cozulen_dosyalar.append(sonuc)
                                    self.rapor.cozum_ekle({
                                        "dosya_yolu": dosya_yolu,
                                        "basarili": True,
                                        "algoritma": f"AES-{len(anahtar_baytlari)*8}-{mod.upper()}",
                                        "dogrulanan_tur": sonuc.get("dogrulanan_tur")
                                    })
                                    cubuk.animasyonlu_tamamla(
                                        hedef_dosya=sonuc.get("hedef_yol") or dosya_adi,
                                        basarili=True,
                                        detay=f"AES-{len(anahtar_baytlari)*8}-{mod.upper()} -> {sonuc.get('dogrulanan_tur')}"
                                    )
                                    break
                            if cozum_basarili:
                                break
                        except Exception:
                            continue

            if not cozum_basarili:
                cubuk.guncelle(65, asama="Yapısal rekonstrüksiyon")
                dengeli_bekle(0.05)
                try:
                    yapisal_motor = YapisalKurtarmaMotoru(
                        kuru_calistirma=self.kuru_calistirma,
                        cikti_dizini=self.cikti_dizini
                    )
                    y_sonuc = yapisal_motor.otonom_yapisal_kurtar(dosya_yolu)
                    if y_sonuc.get("basarili"):
                        cozum_basarili = True
                        k_turu = y_sonuc.get("kurtarma_turu", "Deep Structural Carving")
                        self.cozulen_dosyalar.append(y_sonuc)
                        self.rapor.cozum_ekle({
                            "dosya_yolu": dosya_yolu,
                            "basarili": True,
                            "algoritma": k_turu,
                            "dogrulanan_tur": uzanti.lstrip(".")
                        })
                        cubuk.animasyonlu_tamamla(
                            hedef_dosya=y_sonuc.get("hedef_yol") or y_sonuc.get("cikti_dosya") or dosya_adi,
                            basarili=True,
                            detay=k_turu
                        )
                except Exception:
                    pass

            if not cozum_basarili:
                cubuk.guncelle(72, asama="Başlık yamalama")
                dengeli_bekle(0.05)
                baslik_analizi = dosya_baslik_analizi_yap(dosya_yolu)
                if baslik_analizi.get("baslik_bozulmus_mu"):
                    tahmin_edilen = baslik_analizi.get("mevcut_uzanti", "").lstrip(".")
                    if tahmin_edilen in ("pdf", "png", "jpg", "jpeg", "zip", "sqlite"):
                        yama_sonucu = baslik_yama(dosya_yolu, hedef_format=tahmin_edilen)
                        if yama_sonucu.get("basarili"):
                            cozum_basarili = True
                            self.cozulen_dosyalar.append(yama_sonucu)
                            self.rapor.cozum_ekle({
                                "dosya_yolu": dosya_yolu,
                                "basarili": True,
                                "algoritma": "Magic Byte Header Patching",
                                "dogrulanan_tur": tahmin_edilen
                            })
                            cubuk.animasyonlu_tamamla(
                                hedef_dosya=yama_sonucu.get("onarilan_dosya") or dosya_adi,
                                basarili=True,
                                detay=f"Header Patch -> {tahmin_edilen}"
                            )

            if not cozum_basarili:
                cubuk.guncelle(78, asama="Zaman tabanlı PRNG kırıcı")
                dengeli_bekle(0.05)
                try:
                    zaman = dosya_zaman_damgasi_al(dosya_yolu)
                    with open(dosya_yolu, "rb") as f:
                        sifreli_baytlar = f.read(1024)
                    kok_isim, _ = os.path.splitext(dosya_yolu)
                    tahmini_uzanti = (os.path.splitext(kok_isim)[1] or uzanti).lstrip(".").lower() or None
                    kirma = zaman_tabanli_xor_kir(
                        sifreli_baytlar,
                        merkez_zaman=zaman,
                        aralik_saniye=600,
                        beklenen_uzanti=tahmini_uzanti
                    )
                    if kirma and kirma.get("basarili"):
                        anahtar_hex = kirma.get("kurtarilan_anahtar_hex") or kirma.get("anahtar_hex")
                        if anahtar_hex:
                            anahtar_bayt = bytes.fromhex(anahtar_hex)
                            xor_c = XorCozucu(
                                anahtar_baytlari=anahtar_bayt,
                                kuru_calistirma=self.kuru_calistirma,
                                yedek_al=self.yedek_al,
                                hedef_cikti_dizini=self.cikti_dizini
                            )
                            x_sonuc = xor_c.tekil_dosya_coz(dosya_yolu, animasyon=False)
                            if x_sonuc.get("basarili"):
                                cozum_basarili = True
                                self.cozulen_dosyalar.append(x_sonuc)
                                self.rapor.cozum_ekle({
                                    "dosya_yolu": dosya_yolu,
                                    "basarili": True,
                                    "algoritma": "Zaman-Tabanli PRNG XOR",
                                    "dogrulanan_tur": x_sonuc.get("dogrulanan_tur")
                                })
                                cubuk.animasyonlu_tamamla(
                                    hedef_dosya=x_sonuc.get("hedef_yol") or dosya_adi,
                                    basarili=True,
                                    detay=f"PRNG XOR (Key: {anahtar_hex[:8]}...)"
                                )
                except Exception:
                    pass

            if not cozum_basarili:
                cubuk.guncelle(84, asama="Bilinen düz metin (KPA)")
                dengeli_bekle(0.05)
                try:
                    with open(dosya_yolu, "rb") as f:
                        sifreli_baytlar = f.read(1024)
                    kok_isim, _ = os.path.splitext(dosya_yolu)
                    tahmini_uzanti = (os.path.splitext(kok_isim)[1] or uzanti).lstrip(".").lower()
                    if tahmini_uzanti in BILINEN_SIHIRLI_BAYTLAR:
                        duz_imza = BILINEN_SIHIRLI_BAYTLAR[tahmini_uzanti]
                        kpa_sonuc = bilinen_metin_saldirisi_yap(duz_imza, sifreli_baytlar[:len(duz_imza)])
                        if kpa_sonuc.get("kurtarilan_anahtar_hex"):
                            k_bayt = bytes.fromhex(kpa_sonuc["kurtarilan_anahtar_hex"])
                            xor_c = XorCozucu(
                                anahtar_baytlari=k_bayt,
                                kuru_calistirma=self.kuru_calistirma,
                                yedek_al=self.yedek_al,
                                hedef_cikti_dizini=self.cikti_dizini
                            )
                            x_res = xor_c.tekil_dosya_coz(dosya_yolu, animasyon=False)
                            if x_res.get("basarili") and x_res.get("dogrulanan_tur"):
                                cozum_basarili = True
                                self.cozulen_dosyalar.append(x_res)
                                self.rapor.cozum_ekle({
                                    "dosya_yolu": dosya_yolu,
                                    "basarili": True,
                                    "algoritma": "Bilinen Düz Metin (KPA) XOR",
                                    "dogrulanan_tur": x_res.get("dogrulanan_tur")
                                })
                                cubuk.animasyonlu_tamamla(
                                    hedef_dosya=x_res.get("hedef_yol") or dosya_adi,
                                    basarili=True,
                                    detay=f"KPA XOR -> {x_res.get('dogrulanan_tur')}"
                                )
                except Exception:
                    pass

            if not cozum_basarili:
                try:
                    alg_uretici = OtonomAlgoritmaUretici(
                        kuru_calistirma=self.kuru_calistirma,
                        yedek_al=self.yedek_al,
                        hedef_cikti_dizini=self.cikti_dizini
                    )
                    sentez_sonucu = alg_uretici.algoritma_sentezle_ve_coz(dosya_yolu, cubuk=cubuk)
                    if sentez_sonucu.get("basarili"):
                        cozum_basarili = True
                        s_alg = sentez_sonucu.get("sentezlenen_algoritma", "Dinamik Sentez")
                        s_tur = sentez_sonucu.get("dogrulanan_tur", "Bilinmiyor")
                        self.cozulen_dosyalar.append(sentez_sonucu)
                        self.rapor.cozum_ekle({
                            "dosya_yolu": dosya_yolu,
                            "basarili": True,
                            "algoritma": f"Otonom Sentez: {s_alg}",
                            "dogrulanan_tur": s_tur
                        })
                        cubuk.animasyonlu_tamamla(
                            hedef_dosya=sentez_sonucu.get("cikti") or dosya_adi,
                            basarili=True,
                            detay=f"{s_alg} -> {s_tur}"
                        )
                except Exception:
                    pass

            if not cozum_basarili:
                try:
                    ai_motor = LokalYapayZekaMotoru(
                        kuru_calistirma=self.kuru_calistirma,
                        yedek_al=self.yedek_al,
                        hedef_cikti_dizini=self.cikti_dizini
                    )
                    ai_sonuc = ai_motor.yapay_zeka_ile_coz(dosya_yolu, cubuk=cubuk)
                    if ai_sonuc.get("basarili"):
                        cozum_basarili = True
                        ai_alg = ai_sonuc.get("sentezlenen_algoritma", "Lokal Yapay Zeka")
                        ai_tur = ai_sonuc.get("dogrulanan_tur", "Bilinmiyor")
                        self.cozulen_dosyalar.append(ai_sonuc)
                        self.rapor.cozum_ekle({
                            "dosya_yolu": dosya_yolu,
                            "basarili": True,
                            "algoritma": f"Lokal Yapay Zeka: {ai_alg}",
                            "dogrulanan_tur": ai_tur
                        })
                        cubuk.animasyonlu_tamamla(
                            hedef_dosya=ai_sonuc.get("cikti") or dosya_adi,
                            basarili=True,
                            detay=f"{ai_alg} -> {ai_tur}"
                        )
                except Exception:
                    pass

            if not cozum_basarili:
                # etkileşimli moddaysa kullanıcıdan parola veya anahtar ister.
                if self.interaktif_sor and sys.stdin.isatty():
                    try:
                        from rescat.yardimcilar.konsol import uyari_yaz, bilgi_yaz, basari_yaz, tablo_satiri_yaz
                        cubuk.animasyonlu_tamamla(hedef_dosya=dosya_adi, basarili=False)
                        print("\n")
                        uyari_yaz(f"[ANALİZ] {dosya_adi}: Otomatik anahtar tespiti tamamlandı.")
                        tablo_satiri_yaz("Kripto Tespiti", algo_adi)
                        tablo_satiri_yaz("Dosya Boyutu", f"{os.path.getsize(dosya_yolu)} bayt")
                        if sifreli_on_baytlar.startswith(b"Salted__"):
                            tablo_satiri_yaz("Özel Format", f"OpenSSL Salted (Tuz: {sifreli_on_baytlar[8:16].hex()})")

                        girdi = input("\n  [?] Bu dosya için bilinen parola, anahtar (HEX) veya fidye şifresini girin (Atlamak için Enter): ").strip()
                        if girdi:
                            bilgi_yaz(f"Girilen parola/anahtar deneniyor: '{girdi}'...")
                            deneme_cozum = None
                            # 1. openssl denemesi.
                            if sifreli_on_baytlar.startswith(b"Salted__"):
                                from rescat.cozuculer.openssl_cozucu import OpenSslCozucu
                                for algo in ("aes-256-cbc", "aes-128-cbc"):
                                    op = OpenSslCozucu(
                                        parola_veya_anahtar=girdi.encode("utf-8"),
                                        algoritma_adi=algo,
                                        kuru_calistirma=self.kuru_calistirma,
                                        yedek_al=self.yedek_al,
                                        hedef_cikti_dizini=self.cikti_dizini
                                    )
                                    res = op.tekil_dosya_coz(dosya_yolu)
                                    if res.get("basarili") and res.get("dogrulanan_tur"):
                                        deneme_cozum = res
                                        break
                            # 2. evrensel fabrika denemesi.
                            if not deneme_cozum:
                                try:
                                    k_bayt = bytes.fromhex(girdi)
                                except Exception:
                                    k_bayt = girdi.encode("utf-8")
                                for algo in ("aes", "chacha20", "twofish", "blowfish", "rc4", "xor"):
                                    try:
                                        coz = CozucuFabrikasi.cozucu_uret(
                                            algoritma=algo,
                                            anahtar_baytlari=k_bayt,
                                            kuru_calistirma=self.kuru_calistirma,
                                            yedek_al=self.yedek_al,
                                            hedef_cikti_dizini=self.cikti_dizini
                                        )
                                        res = coz.tekil_dosya_coz(dosya_yolu)
                                        if res.get("basarili") and res.get("dogrulanan_tur"):
                                            deneme_cozum = res
                                            break
                                    except Exception:
                                        pass

                            if deneme_cozum and deneme_cozum.get("basarili"):
                                cozum_basarili = True
                                self.cozulen_dosyalar.append(deneme_cozum)
                                self.rapor.cozum_ekle({
                                    "dosya_yolu": dosya_yolu,
                                    "basarili": True,
                                    "algoritma": f"Kullanıcı Destekli: {algo_adi}",
                                    "dogrulanan_tur": deneme_cozum.get("dogrulanan_tur")
                                })
                                basari_yaz(f"[+] BAŞARIYLA KURTARILDI: {dosya_adi} ({deneme_cozum.get('dogrulanan_tur')})")
                    except Exception:
                        pass

                if not cozum_basarili:
                    if not (self.interaktif_sor and sys.stdin.isatty()):
                        cubuk.animasyonlu_tamamla(hedef_dosya=dosya_adi, basarili=False)

                    # adli bilişim kurtarma taraması.
                    try:
                        from rescat.analizciler.adli_kurtarma import AdliKurtarmaMotoru
                        adli_mot = AdliKurtarmaMotoru(cikti_dizini=self.cikti_dizini)
                        adli_sonuc = adli_mot.tam_adli_kurtarma_yurut(dosya_yolu)
                        if adli_sonuc.get("toplam_kurtarilabilir_oge", 0) > 0:
                            uyari_yaz(
                                f"[ADLİ BİLİŞİM] {dosya_adi} için {adli_sonuc['toplam_kurtarilabilir_oge']} alternatif kurtarma izi tespit edildi "
                                f"(Gölge Kopya / Geçici Ofis Artığı / WAL) -> {self.cikti_dizini}"
                            )
                    except Exception:
                        pass

                    self.rapor.cozum_ekle({
                        "dosya_yolu": dosya_yolu,
                        "basarili": False,
                        "algoritma": algo_adi,
                        "dogrulanan_tur": None
                    })

    def raporlari_kaydet(self) -> Dict[str, str]:
        toplam_sifreli = len(self.sifreli_dosyalar)
        toplam_cozulen = len([c for c in self.cozulen_dosyalar if c.get("basarili")])

        self.rapor.ozet_ekle({
            "Hedef Dizin": self.hedef_dizin,
            "Masaüstü Çıktı Dizini": self.cikti_dizini,
            "Calisma Modu": "100% Cevrimdisi Otonom",
            "Toplam Sifreli Dosya": str(toplam_sifreli),
            "Basariyla Kurtarilan Dosyalar": str(toplam_cozulen),
            "Kurtarma Orani": f"%{(toplam_cozulen / toplam_sifreli * 100):.1f}" if toplam_sifreli > 0 else "%0.0"
        })

        entropi_haritasi = None
        if self.sifreli_dosyalar:
            try:
                with open(self.sifreli_dosyalar[0], "rb") as o_dosya:
                    ornek_veri = o_dosya.read(2 * 1024 * 1024)
                    entropi_haritasi = kayan_pencere_entropisi(ornek_veri)
            except Exception:
                pass

        json_yolu = os.path.join(self.cikti_dizini, "kurtarma_raporu.json")
        md_yolu = os.path.join(self.cikti_dizini, "kurtarma_raporu.md")
        html_yolu = os.path.join(self.cikti_dizini, "kurtarma_raporu.html")

        self.rapor.json_olarak_kaydet(json_yolu)
        self.rapor.markdown_olarak_kaydet(md_yolu)
        self.rapor.html_olarak_kaydet(html_yolu, entropi_haritasi=entropi_haritasi)

        return {
            "json": json_yolu,
            "markdown": md_yolu,
            "html": html_yolu
        }

    def calistir(self) -> Dict[str, Any]:
        self.dosyalari_kesfet()
        if self.bellek_dokumleri:
            self.bellek_anahtarlarini_avla()
        self.dosyalari_otonom_coz()

        toplam_sifreli = len(self.sifreli_dosyalar)
        toplam_cozulen = len([c for c in self.cozulen_dosyalar if c.get("basarili")])

        self.rapor.ozet_ekle({
            "Hedef Dizin": self.hedef_dizin,
            "Masaüstü Kurtarma Dizini": self.cikti_dizini,
            "Çalışma Modu": "100% Çevrimdışı Otonom",
            "Toplam Şifreli Dosya": str(toplam_sifreli),
            "Başarıyla Kurtarılan Dosyalar": str(toplam_cozulen),
            "Kurtarma Oranı": f"%{(toplam_cozulen / toplam_sifreli * 100):.1f}" if toplam_sifreli > 0 else "%0.0"
        })

        if self.rapor_diske_kaydet:
            rapor_yollari = self.raporlari_kaydet()
        else:
            rapor_yollari = {"konsolda_gosterildi": True}

        return {
            "basarili": True,
            "sifreli_dosyalar": self.sifreli_dosyalar,
            "bellek_dokumleri": self.bellek_dokumleri,
            "kurtarilan_anahtarlar": self.kurtarilan_anahtarlar,
            "cozulen_dosyalar": self.cozulen_dosyalar,
            "raporlar": rapor_yollari
        }
