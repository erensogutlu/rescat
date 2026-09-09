import argparse
import os
import sys
import json
import multiprocessing
from typing import Optional

# paketin doğrudan çalıştırılmasını sağlar.
proje_koku = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if proje_koku not in sys.path:
    sys.path.insert(0, proje_koku)
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
    dengeli_bekle
)
from rescat.yardimcilar.raporlayici import Raporlayici
from rescat.yardimcilar.interaktif import interaktif_sihirbaz_baslat
from rescat.cekirdek.entropi import dosya_entropisi_hesapla, kismi_sifreleme_analizi, kayan_pencere_entropisi
from collections import Counter
from rescat.cekirdek.dosya_tanimlayici import dosya_baslik_analizi_yap
from rescat.cekirdek.algoritma_tespit import algoritma_tespit_et, derin_kriptografik_analiz
from rescat.cekirdek.bilinen_metin import bilinen_metin_saldirisi_yap
from rescat.cekirdek.zaman_kirici import dosya_zaman_damgasi_al, zaman_tabanli_xor_kir
from rescat.cekirdek.zayif_rsa import fermat_carpanlara_ayir, wiener_saldirisi, rsa_ozel_anahtar_pem_olustur
from rescat.cekirdek.baslik_onarici import baslik_yama
from rescat.cekirdek.djvu_veritabani import offline_anahtar_mi, uzantiya_gore_offline_anahtar_al
from rescat.analizciler.bellek_anahtar_avcisi import bellek_dosyasini_tara, chacha20_matris_ara, salsa20_matris_ara
from rescat.cozuculer.xor_cozucu import XorCozucu
from rescat.cozuculer.aes_cozucu import AesCozucu
from rescat.cozuculer.chacha_cozucu import ChaChaCozucu
from rescat.cozuculer.rsa_cozucu import RsaCozucu
from rescat.cozuculer.akici_cozucu import AkiciCozucu
from rescat.cozuculer.paralel_cozucu import ParalelCozucu
from rescat.cozuculer.evrensel_cozucu import CozucuFabrikasi
from rescat.cozuculer.poly1305_cozucu import Poly1305Cozucu
from rescat.analizciler.footer_ayristirici import FooterAyristirici
from rescat.otonom import OtonomKurtarmaMotoru
from rescat.cekirdek.yapisal_kurtarici import YapisalKurtarmaMotoru
from rescat.cekirdek.keystream_cozucu import KeystreamCozucu
from rescat.cekirdek.sizinti_veritabani import bilinen_cozucu_tavsiyesi


def komut_otonom(argumanlar: Optional[argparse.Namespace] = None) -> None:
    # tam otonom kurtarma komutu.
    hedef = getattr(argumanlar, "hedef", None) if argumanlar else None
    cikti = getattr(argumanlar, "cikti", None) if argumanlar else None
    cikti = cikti or masaustu_dizini_al()
    kuru = getattr(argumanlar, "kuru_calistirma", False) if argumanlar else False
    yedeksiz = getattr(argumanlar, "yedeksiz", False) if argumanlar else False

    motor = OtonomKurtarmaMotoru(
        hedef=hedef,
        cikti_dizini=cikti,
        kuru_calistirma=kuru,
        yedek_al=not yedeksiz
    )
    motor.calistir()



def komut_genel_tarama(argumanlar: Optional[argparse.Namespace] = None) -> None:
    # ortam genelinde otomatik tarama ve şifre çözümü.
    hedef = getattr(argumanlar, "hedef", ".") if argumanlar else "."
    hedef = os.path.abspath(hedef)
    cikti = getattr(argumanlar, "cikti", None) if argumanlar else None
    cikti = cikti or masaustu_dizini_al()
    kuru = getattr(argumanlar, "kuru_calistirma", False) if argumanlar else False
    yedeksiz = getattr(argumanlar, "yedeksiz", False) if argumanlar else False

    motor = OtonomKurtarmaMotoru(
        hedef=hedef,
        cikti_dizini=cikti,
        kuru_calistirma=kuru,
        yedek_al=not yedeksiz
    )
    motor.calistir()


def komut_ozel_tarama(argumanlar: argparse.Namespace) -> None:
    # tekil dosyaya odaklı özel tarama ve şifre çözümü.
    hedef = getattr(argumanlar, "hedef", None)
    if not hedef:
        hata_yaz("Özel tarama için bir dosya veya dizin belirtmelisiniz.")
        return

    hedef = os.path.abspath(hedef)
    uzanti_filtresi = getattr(argumanlar, "uzanti", None)
    cikti = getattr(argumanlar, "cikti", None) or masaustu_dizini_al()
    kuru = getattr(argumanlar, "kuru_calistirma", False)
    yedeksiz = getattr(argumanlar, "yedeksiz", False)

    motor = OtonomKurtarmaMotoru(
        hedef=hedef,
        uzanti_filtresi=uzanti_filtresi,
        cikti_dizini=cikti,
        kuru_calistirma=kuru,
        yedek_al=not yedeksiz
    )
    motor.calistir()


def komut_analiz(argumanlar: argparse.Namespace) -> None:
    # adli bilişim ve kriptografik analiz komutu.
    hedef = getattr(argumanlar, "hedef", ".")
    if not os.path.exists(hedef):
        hata_yaz(f"Hedef bulunamadı: {hedef}")
        return

    rapor_dosyasi = getattr(argumanlar, "rapor", None)
    oto_coz = getattr(argumanlar, "coz", False)

    if os.path.isfile(hedef):
        baslik_yaz(f"Derin Kriptografik Analiz: {os.path.basename(hedef)}")
        analiz = derin_kriptografik_analiz(hedef)

        tablo_satiri_yaz("Dosya Yolu", analiz["dosya_yolu"])
        tablo_satiri_yaz("Dosya Boyutu", f"{analiz['dosya_boyutu']:,} bayt")
        tablo_satiri_yaz("Şifreli mi", "EVET" if analiz["sifreli_mi"] else "HAYIR")
        tablo_satiri_yaz("Birincil Algoritma", f"{analiz['birincil_algoritma']} (Güven: %{int(analiz['guven_skoru']*100)})")
        tablo_satiri_yaz("Shannon Entropisi", f"{analiz['entropi']} / 8.00")
        tablo_satiri_yaz("Ki-Kare Skoru (Chi^2)", f"{analiz['ki_kare_skoru']} (Rastgelelik: %{analiz['rastgelelik_orani']})")
        tablo_satiri_yaz("Seri Korelasyon", str(analiz["seri_korelasyon"]))
        tablo_satiri_yaz("Blok Boyutu & Mod", f"{analiz['blok_boyutu']} Bayt ({analiz['tahmini_mod']})")

        # dosya sonu ve üst veri analizi.
        footer_parser = FooterAyristirici()
        footer_bilgi = footer_parser.dosyayi_ayristir(hedef)
        if footer_bilgi.get("kurban_id"):
            tablo_satiri_yaz("Footer Kurban Kimliği", str(footer_bilgi["kurban_id"]))
        if footer_bilgi.get("olasi_asimetrik_anahtar_blobu"):
            blob = footer_bilgi["olasi_asimetrik_anahtar_blobu"]
            tablo_satiri_yaz("Footer Asimetrik Zarf", f"{blob['tahmini_asimetrik_tip']} ({blob['boyut_bayt']}B, Entropi: {blob['entropi']})")

        if analiz.get("tehdit_istihbarati"):
            t = analiz["tehdit_istihbarati"]
            uyari_yaz(f"Tehdit İstihbaratı Eşleşti: {t.get('zararli', 'Bilinmiyor')}")
            tablo_satiri_yaz("  Açıklama", t.get("aciklama", t.get("durum", "")))
            if t.get("anahtar_hex"):
                basari_yaz(f"  Sızdırılmış Master Anahtar: {t['anahtar_hex']}")

        if analiz.get("cozucu_tavsiyesi"):
            tav = analiz["cozucu_tavsiyesi"]
            bilgi_yaz(f"Çözücü Durumu: {tav['durum']} (Komut: {tav['arac_baglantisi']})")

        baslik_yaz("Kütüphane Algoritma Adayları Matrisi (Öncelikli Sıralama)")
        for idx, aday in enumerate(analiz.get("aday_algoritmalar", [])[:8], start=1):
            tablo_satiri_yaz(
                f"#{idx} {aday['ad']}",
                f"Olasılık: %{int(aday['olasilik']*100)} | Blok: {aday['blok']}B | Tür: {aday['kategori']}"
            )

        baslik_yaz("Önerilen Çözüm Komutu")
        basari_yaz(analiz["komut_onerisi"])

        if rapor_dosyasi:
            import json
            with open(rapor_dosyasi, "w", encoding="utf-8") as rf:
                json.dump(analiz, rf, ensure_ascii=False, indent=2)
            basari_yaz(f"Analiz raporu kaydedildi: {rapor_dosyasi}")

        stix_dosyasi = getattr(argumanlar, "stix_rapor", None)
        if stix_dosyasi:
            raporcu = Raporlayici(vaka_adi=f"analiz_{os.path.basename(hedef)}")
            raporcu.dosya_analizi_ekle(analiz)
            raporcu.ozet_ekle({
                "Hedef": hedef,
                "Tespit Edilen Zararlı Ailesi": analiz.get("birincil_algoritma", "Bilinmiyor"),
                "Şifreli Mi": analiz.get("sifreli_mi", True)
            })
            raporcu.stix_olarak_kaydet(stix_dosyasi)
            basari_yaz(f"OASIS STIX 2.1 Adli Raporu Kaydedildi: {stix_dosyasi}")

        if oto_coz:
            bilgi_yaz("Otomatik çözüm aşamasına geçiliyor...")
            komut_ozel_tarama(argumanlar)

    else:
        # dizin analizi.
        baslik_yaz(f"Dizin Kriptografik ve Tehdit Analizi: {hedef}")
        analiz_listesi = []
        for kok, _, dosyalar in os.walk(hedef):
            for d in dosyalar:
                tam = os.path.join(kok, d)
                if not os.path.isfile(tam) or os.path.getsize(tam) == 0:
                    continue
                try:
                    res = algoritma_tespit_et(tam)
                    if res.get("sifreli_mi"):
                        analiz_listesi.append(res)
                except Exception:
                    pass

        tablo_satiri_yaz("Taranan Dizin", hedef)
        tablo_satiri_yaz("Tespit Edilen Şifreli Dosya", str(len(analiz_listesi)))

        algoritma_sayimi = Counter(a.get("algoritma", "Bilinmiyor") for a in analiz_listesi)
        baslik_yaz("Dizindeki Algoritma Dağılımı")
        for algo, count in algoritma_sayimi.most_common():
            tablo_satiri_yaz(algo, f"{count} dosya")

        stix_dosyasi = getattr(argumanlar, "stix_rapor", None)
        if stix_dosyasi:
            raporcu = Raporlayici(vaka_adi=f"dizin_analizi_{os.path.basename(hedef)}")
            for a in analiz_listesi:
                raporcu.dosya_analizi_ekle(a)
            raporcu.ozet_ekle({
                "Taranan Dizin": hedef,
                "Toplam Şifreli Dosya": len(analiz_listesi),
                "Tespit Edilen Zararlı Ailesi": "Ransomware Multi-Target"
            })
            raporcu.stix_olarak_kaydet(stix_dosyasi)
            basari_yaz(f"OASIS STIX 2.1 Dizin Adli Raporu Kaydedildi: {stix_dosyasi}")

        if rapor_dosyasi:
            import json
            with open(rapor_dosyasi, "w", encoding="utf-8") as rf:
                json.dump({"hedef_dizin": hedef, "toplam_sifreli": len(analiz_listesi), "dosyalar": analiz_listesi}, rf, ensure_ascii=False, indent=2)
            basari_yaz(f"Dizin analiz raporu kaydedildi: {rapor_dosyasi}")

        if oto_coz:
            bilgi_yaz("Otomatik genel tarama ve kurtarmaya geçiliyor...")
            komut_genel_tarama(argumanlar)


def komut_kpa(argumanlar: argparse.Namespace) -> None:
    # bilinen düz metin saldırısı ile anahtar çıkarma.
    baslik_yaz("Bilinen Düz Metin Saldırısı (Known-Plaintext Attack)")
    if not os.path.exists(argumanlar.orijinal) or not os.path.exists(argumanlar.sifreli):
        hata_yaz("Orijinal veya şifreli dosya bulunamadı.")
        return

    with open(argumanlar.orijinal, "rb") as dosya_orijinal:
        orijinal_veri = dosya_orijinal.read()
    with open(argumanlar.sifreli, "rb") as dosya_sifreli:
        sifreli_veri = dosya_sifreli.read()

    sonuc = bilinen_metin_saldirisi_yap(orijinal_veri, sifreli_veri)

    tablo_satiri_yaz("Karşılaştırılan Bayt", f"{sonuc['karsilastirilan_bayt_sayisi']} bayt")
    tablo_satiri_yaz("Statik XOR mu", "Evet" if sonuc["statik_xor_mu"] else "Hayır / Karmaşık Akış")
    if sonuc.get("tahmin_edilen_periyot"):
        tablo_satiri_yaz("Anahtar Periyodu", f"{sonuc['tahmin_edilen_periyot']} bayt")
    if sonuc.get("kurtarilan_anahtar_hex"):
        basari_yaz(f"Kurtarılan anahtar (HEX)  : {sonuc['kurtarilan_anahtar_hex']}")
        basari_yaz(f"Kurtarılan anahtar (ASCII): {sonuc['kurtarilan_anahtar_ascii']}")
    else:
        bilgi_yaz(f"Anahtar akışı (ilk 32 bayt): {sonuc['anahtar_akisi_ilk_32_hex']}")


def komut_avci(argumanlar: argparse.Namespace) -> None:
    # bellekten kriptografik anahtar avlama.
    baslik_yaz("Bellek ve Dosya Kriptografik Anahtar Avcısı (AES / Salsa20 / ChaCha20 / TEA / RC4 / RSA / Twofish)")
    hedef_dosya = argumanlar.dosya
    if not os.path.exists(hedef_dosya):
        hata_yaz(f"Dosya bulunamadı: {hedef_dosya}")
        return

    bilgi_yaz(f"Kriptografik anahtar taraması yapılıyor: {hedef_dosya}")
    sonuc = bellek_dosyasini_tara(hedef_dosya)

    if "hata" in sonuc:
        hata_yaz(f"Tarama hatası: {sonuc['hata']}")
        return

    if sonuc.get("dogrulanmis_aes128_anahtarlari"):
        basari_yaz("Doğrulanmış AES-128 anahtarları:")
        for anahtar in sonuc["dogrulanmis_aes128_anahtarlari"]:
            tablo_satiri_yaz("AES-128 Anahtarı (HEX)", anahtar)

    if sonuc.get("dogrulanmis_aes256_anahtarlari"):
        basari_yaz("Doğrulanmış AES-256 anahtarları:")
        for anahtar in sonuc["dogrulanmis_aes256_anahtarlari"]:
            tablo_satiri_yaz("AES-256 Anahtarı (HEX)", anahtar)

    if sonuc.get("salsa20_anahtarlari"):
        basari_yaz("Bulunan Salsa20 durum matrisi ve anahtarları:")
        for s in sonuc["salsa20_anahtarlari"]:
            tablo_satiri_yaz(f"salsa20 ({s['tur']})", f"Key: {s['anahtar_hex']} | Nonce: {s.get('nonce_hex', '')}")

    if sonuc.get("chacha20_anahtarlari"):
        basari_yaz("Bulunan ChaCha20 durum matrisi ve anahtarları:")
        for c in sonuc["chacha20_anahtarlari"]:
            tablo_satiri_yaz(f"chacha20 ({c['tur']})", f"Key: {c['anahtar_hex']} | Nonce: {c.get('nonce_ietf_hex', '')}")

    if sonuc.get("tea_anahtarlari"):
        basari_yaz("Bulunan TEA/XTEA delta ve 128-bit anahtar adayları:")
        for t in sonuc["tea_anahtarlari"]:
            tablo_satiri_yaz("TEA/XTEA Anahtar Adayı", t["anahtar_hex"])

    if sonuc.get("rc4_durumlari"):
        basari_yaz(f"{len(sonuc['rc4_durumlari'])} adet aktif RC4 S-Box permütasyonu tespit edildi:")
        for r in sonuc["rc4_durumlari"]:
            tablo_satiri_yaz(f"rc4 ofset {hex(r['ofset'])}", f"S-Box ilk 16 bayt: {r['onizleme_hex']}")

    if sonuc.get("olasi_192bit_adaylari"):
        bilgi_yaz("3DES / AES-192 yüksek entropili aday anahtarlar:")
        for a in sonuc["olasi_192bit_adaylari"][:5]:
            tablo_satiri_yaz("192-bit aday (hex)", a)

    if sonuc.get("olasi_256bit_adaylari"):
        bilgi_yaz("Twofish / AES-256 / Camellia yüksek entropili aday anahtarlar:")
        for a in sonuc["olasi_256bit_adaylari"][:5]:
            tablo_satiri_yaz("256-bit aday (hex)", a)

    if sonuc.get("rsa_anahtar_sayisi", 0) > 0:
        basari_yaz(f"{sonuc['rsa_anahtar_sayisi']} adet RSA özel anahtarı bulundu!")
        for indeks, rsa_pem in enumerate(sonuc["rsa_anahtarlari"], start=1):
            bilgi_yaz(f"--- RSA Anahtarı #{indeks} ---")
            print(rsa_pem[:150] + "\n...")


def komut_zaman_kirici(argumanlar: argparse.Namespace) -> None:
    # zaman tabanlı tohum kırıcı komutu.
    baslik_yaz("Zaman Tabanlı PRNG Anahtar Kırıcı")
    hedef_dosya = argumanlar.dosya
    if not os.path.exists(hedef_dosya):
        hata_yaz(f"Dosya bulunamadı: {hedef_dosya}")
        return

    merkez_zaman = argumanlar.zaman or dosya_zaman_damgasi_al(hedef_dosya)
    bilgi_yaz(f"Merkez zaman damgası: {merkez_zaman}")

    with open(hedef_dosya, "rb") as dosya_nesnesi:
        okunan_baytlar = dosya_nesnesi.read(1024)

    bilgi_yaz(f"+/- {argumanlar.aralik} saniyelik tohum uzayi taranıyor...")
    sonuc = zaman_tabanli_xor_kir(
        okunan_baytlar,
        merkez_zaman=merkez_zaman,
        aralik_saniye=argumanlar.aralik,
        anahtar_uzunlugu=argumanlar.uzunluk,
        beklenen_uzanti=argumanlar.format
    )

    if sonuc and sonuc.get("basarili"):
        basari_yaz("Anahtar ve tohum başarıyla kırıldı!")
        tablo_satiri_yaz("Kurtarılan Tohum (Seed)", str(sonuc["kurtarilan_tohum"]))
        tablo_satiri_yaz("Zaman Farkı (Saniye)", str(sonuc["zaman_farki_saniye"]))
        tablo_satiri_yaz("Kurtarılan Anahtar (HEX)", sonuc["anahtar_hex"])
        tablo_satiri_yaz("Doğrulanan Dosya Türü", str(sonuc["dogrulanan_tur"]))
    else:
        uyari_yaz("Belirtilen zaman aralığında tohum bulunamadı. Aralık parametresini artırmayı deneyin (--aralik)")


def komut_zayif_rsa(argumanlar: argparse.Namespace) -> None:
    # zayıf rsa anahtarlarını kıran komut.
    baslik_yaz("Zayıf RSA Çarpanlara Ayırma ve Özel Anahtar Kurtarma")

    if argumanlar.yontem == "fermat":
        bilgi_yaz(f"Fermat algoritması ile modül n çarpanlarına ayrılıyor...")
        carpanlar = fermat_carpanlara_ayir(argumanlar.n, maksimum_adim=argumanlar.adim)
        if carpanlar:
            p, q = carpanlar
            basari_yaz("Modül n başarıyla çarpanlarına ayrıldı!")
            tablo_satiri_yaz("Asal Çarpan p", str(p))
            tablo_satiri_yaz("Asal Çarpan q", str(q))
            if argumanlar.cikti:
                pem = rsa_ozel_anahtar_pem_olustur(p, q, genel_us_e=argumanlar.e)
                with open(argumanlar.cikti, "wb") as f_cikti:
                    f_cikti.write(pem)
                basari_yaz(f"Kurtarılan RSA özel anahtarı kaydedildi: {argumanlar.cikti}")
        else:
            uyari_yaz("Fermat yöntemiyle çarpan bulunamadı (p ve q yeterince yakın değil)")

    elif argumanlar.yontem == "wiener":
        bilgi_yaz("Küçük özel üs d için Wiener sürekli kesir saldırısı çalıştırılıyor...")
        sonuc = wiener_saldirisi(argumanlar.e, argumanlar.n)
        if sonuc:
            d, p, q = sonuc
            basari_yaz("Wiener saldırısı başarılı! Özel üs kurtarıldı.")
            tablo_satiri_yaz("Gizli Üs d", str(d))
            tablo_satiri_yaz("Asal Çarpan p", str(p))
            tablo_satiri_yaz("Asal Çarpan q", str(q))
            if argumanlar.cikti:
                pem = rsa_ozel_anahtar_pem_olustur(p, q, genel_us_e=argumanlar.e)
                with open(argumanlar.cikti, "wb") as f_cikti:
                    f_cikti.write(pem)
                basari_yaz(f"Kurtarılan RSA özel anahtarı kaydedildi: {argumanlar.cikti}")
        else:
            uyari_yaz("Wiener saldırısı başarısız (d > 1/3 * n^(1/4) olabilir)")


def komut_onar(argumanlar: argparse.Namespace) -> None:
    # hasarlı dosya başlığını onarma.
    baslik_yaz("Kısmi Şifrelenmiş Dosya Başlığı Onarıcı (Header Patching)")
    sonuc = baslik_yama(
        hasarli_dosya_yolu=argumanlar.dosya,
        hedef_format=argumanlar.format,
        cikti_dosya_yolu=argumanlar.cikti,
        ezilen_bayt_boyutu=argumanlar.ezilen_boyut
    )

    if sonuc.get("basarili"):
        basari_yaz(f"Dosya başarıyla onarıldı: {sonuc['onarilan_dosya']}")
        tablo_satiri_yaz("Uygulanan Format", sonuc["format"])
        tablo_satiri_yaz("Eklenen Başlık", f"{sonuc['eklenen_baslik_boyutu']} bayt")
        tablo_satiri_yaz("Kurtarılan Gövde", f"{sonuc['kurtarilan_govde_boyutu']:,} bayt")
    else:
        hata_yaz(f"Onarma hatası: {sonuc.get('hata')}")



def komut_coz(argumanlar: argparse.Namespace) -> None:
    # dosya veya dizin şifresini çözme.
    baslik_yaz("Fidye Yazılımı Dosya Deşifreleme (Decryptor)")
    hedef = argumanlar.hedef
    if not os.path.exists(hedef):
        hata_yaz(f"Hedef dosya veya dizin bulunamadı: {hedef}")
        return

    # parametre belirtilmediğinde otomatik motoru çalıştırır.
    cikti_konumu = getattr(argumanlar, "cikti", None) or masaustu_dizini_al()
    if not getattr(argumanlar, "algoritma", None) or not getattr(argumanlar, "anahtar", None):
        bilgi_yaz("Anahtar veya algoritma belirtilmedi; otomatik tespit ve çözüm motoru başlatılıyor...")
        motor = OtonomKurtarmaMotoru(
            hedef=hedef,
            cikti_dizini=cikti_konumu,
            kuru_calistirma=getattr(argumanlar, "kuru_calistirma", False),
            yedek_al=not getattr(argumanlar, "yedeksiz", False)
        )
        motor.calistir()
        return

    bilgi_yaz(f"Kurtarılan Dosyaların Çıktı Konumu (Masaüstü): {cikti_konumu}")
    algoritma = argumanlar.algoritma.lower()
    anahtar_girdisi = argumanlar.anahtar

    # anahtarı hex veya metin olarak işler.
    if argumanlar.hex:
        try:
            anahtar_baytlari = bytes.fromhex(anahtar_girdisi)
        except ValueError:
            hata_yaz("Geçersiz HEX anahtar dizisi")
            return
    else:
        anahtar_baytlari = anahtar_girdisi.encode("utf-8")

    baslatma_vektoru = None
    if argumanlar.iv:
        baslatma_vektoru = bytes.fromhex(argumanlar.iv) if argumanlar.hex else argumanlar.iv.encode("utf-8")

    # büyük dosyalar için akışkan mod kontrolü.
    if argumanlar.akici and os.path.isfile(hedef):
        bilgi_yaz(f"Akıcı (streaming) çözücü devrede: {hedef}")
        akici_cozucu = AkiciCozucu(
            anahtar_baytlari=anahtar_baytlari,
            algoritma_adi=algoritma,
            mod_adi=argumanlar.mod,
            baslatma_vektoru=baslatma_vektoru,
            yedek_al=not argumanlar.yedeksiz,
            hedef_cikti_dizini=cikti_konumu
        )
        sonuc = akici_cozucu.akiskan_dosya_coz(hedef)
        if sonuc.get("basarili"):
            basari_yaz(f"Büyük dosya başarıyla çözüldü: {sonuc['hedef_dosya']}")
        else:
            hata_yaz(f"Akıcı çözme hatası: {sonuc.get('hata')}")
        return

    # çok çekirdekli paralel mod kontrolü.
    if os.path.isdir(hedef) and argumanlar.paralel:
        bilgi_yaz(f"Dizin {argumanlar.paralel} işlemci çekirdeği ile paralel çözülüyor: {hedef}")
        paralel = ParalelCozucu(
            anahtar_baytlari=anahtar_baytlari,
            algoritma=algoritma,
            mod_adi=argumanlar.mod,
            baslatma_vektoru=baslatma_vektoru,
            is_parcacigi_sayisi=argumanlar.paralel,
            kuru_calistirma=argumanlar.kuru_calistirma,
            yedek_al=not argumanlar.yedeksiz,
            hedef_cikti_dizini=cikti_konumu
        )
        sonuclar = paralel.dizini_paralel_coz(hedef, uzanti_filtresi=argumanlar.uzanti)
        basarili = sum(1 for s in sonuclar if s.get("basarili"))
        basari_yaz(f"toplam {len(sonuclar)} dosyadan {basarili} tanesi paralel olarak cozuldu -> {cikti_konumu}")
        return

    # tekil standart çözücü.
    try:
        if algoritma == "rsa":
            if not os.path.exists(anahtar_girdisi):
                hata_yaz(f"RSA PEM dosyası bulunamadı: {anahtar_girdisi}")
                return
            with open(anahtar_girdisi, "rb") as pem_dosyasi:
                pem_verisi = pem_dosyasi.read()
            cozucu = RsaCozucu(
                ozel_anahtar_pem=pem_verisi,
                dolgu_turu=argumanlar.rsa_dolgu,
                kuru_calistirma=argumanlar.kuru_calistirma,
                yedek_al=not argumanlar.yedeksiz,
                hedef_cikti_dizini=cikti_konumu
            )
        elif algoritma == "xor":
            cozucu = XorCozucu(
                anahtar_baytlari=anahtar_baytlari,
                kaydirmali_mi=argumanlar.kaydirmali,
                kuru_calistirma=argumanlar.kuru_calistirma,
                yedek_al=not argumanlar.yedeksiz,
                hedef_cikti_dizini=cikti_konumu
            )
        else:
            cozucu = CozucuFabrikasi.cozucu_uret(
                algoritma=algoritma,
                anahtar_baytlari=anahtar_baytlari,
                mod=getattr(argumanlar, "mod", "cbc"),
                iv=baslatma_vektoru,
                iv_dosya_basinda_mi=not getattr(argumanlar, "iv_harici", False),
                kuru_calistirma=getattr(argumanlar, "kuru_calistirma", False),
                yedek_al=not getattr(argumanlar, "yedeksiz", False),
                hedef_cikti_dizini=cikti_konumu
            )
    except Exception as hata_detayi:
        hata_yaz(f"Çözücü başlatılamadı: {hata_detayi}")
        return

    if os.path.isfile(hedef):
        sonuc = cozucu.tekil_dosya_coz(hedef)
        if sonuc.get("basarili"):
            basari_yaz(f"Dosya başarıyla çözüldü: {hedef}")
            if sonuc.get("hedef_yol"):
                basari_yaz(f"Kurtarılan dosya konumu (Masaüstü): {sonuc['hedef_yol']}")
            if sonuc.get("dogrulanan_tur"):
                basari_yaz(f"Kurtarılan dosya türü: {sonuc['dogrulanan_tur']}")
        else:
            hata_yaz(f"Çözme hatası: {sonuc.get('hata')}")
    else:
        bilgi_yaz(f"Dizin çözülüyor: {hedef}")
        sonuclar = cozucu.dizin_coz(hedef, uzanti_filtresi=argumanlar.uzanti)
        basarili_sayisi = sum(1 for s in sonuclar if s.get("basarili"))
        basari_yaz(f"Toplam {len(sonuclar)} dosyadan {basarili_sayisi} tanesi çözüldü -> Masaüstüne kaydedildi: {cikti_konumu}")



def komut_yapisal_kurtar(argumanlar: argparse.Namespace) -> None:
    # kısmi şifrelenmiş dosyalarda yapısal kurtarma.
    baslik_yaz("Askeri Standart Kısmi/Aralıklı Şifreleme İçin Yapısal Kurtarma")
    motor = YapisalKurtarmaMotoru(kuru_calistirma=argumanlar.kuru_calistirma)
    if argumanlar.format == "zip":
        sonuc = motor.zip_arsiv_kurtar(argumanlar.dosya, hedef_cikti=argumanlar.cikti)
    elif argumanlar.format == "sqlite":
        sonuc = motor.sqlite_yapraklari_kurtar(argumanlar.dosya, hedef_cikti=argumanlar.cikti)
    elif argumanlar.format == "pdf":
        sonuc = motor.pdf_akis_kurtar(argumanlar.dosya, hedef_cikti=argumanlar.cikti)
    elif argumanlar.format in ("mp4", "mov", "m4v"):
        sonuc = motor.mp4_video_kurtar(argumanlar.dosya, hedef_cikti=argumanlar.cikti)
    elif argumanlar.format in ("jpg", "jpeg", "jfif"):
        sonuc = motor.jpeg_resim_kurtar(argumanlar.dosya, hedef_cikti=argumanlar.cikti)
    else:
        sonuc = motor.otonom_yapisal_kurtar(argumanlar.dosya)

    if sonuc.get("basarili"):
        basari_yaz(f"Yapısal kurtarma başarılı: {sonuc.get('kurtarma_turu')}")
        tablo_satiri_yaz("Kaynak", sonuc.get("kaynak_dosya"))
        tablo_satiri_yaz("Çıktı", sonuc.get("cikti_dosya"))
        if "kurtarilan_ic_dosya_sayisi" in sonuc:
            tablo_satiri_yaz("Kurtarılan İç Dosyalar", str(sonuc["kurtarilan_ic_dosya_sayisi"]))
        if "moov_boyutu" in sonuc:
            tablo_satiri_yaz("Kurtarılan Moov Boyutu", f"{sonuc['moov_boyutu']} bayt")
    else:
        hata_yaz(f"Yapısal kurtarma başarısız: {sonuc.get('hata')}")


def komut_keystream(argumanlar: argparse.Namespace) -> None:
    # nonce tekrarı saldırısı ile çoklu dosya çözümü.
    baslik_yaz("Nonce Reuse & Keystream Replay Çözücü")
    motor = KeystreamCozucu(kuru_calistirma=argumanlar.kuru_calistirma, yedek_al=not argumanlar.yedeksiz)

    hedef = argumanlar.hedef
    dosyalar = []
    if os.path.isfile(hedef):
        dosyalar = [hedef]
    elif os.path.isdir(hedef):
        for k, _, ds in os.walk(hedef):
            for d in ds:
                dosyalar.append(os.path.join(k, d))

    sonuc = motor.coklu_keystream_cozumu(
        referans_orijinal_dosya=argumanlar.referans_orj,
        referans_sifreli_dosya=argumanlar.referans_sifreli,
        hedef_dizin_veya_dosyalar=dosyalar
    )
    if sonuc.get("basarili"):
        basari_yaz(f"Keystream başarıyla çıkarıldı ({sonuc.get('keystream_uzunlugu')} bayt)")
        basari_yaz(f"Toplam {sonuc.get('cozulen_toplam_dosya')} dosya anahtarsız çözüldü!")
    else:
        hata_yaz(f"Keystream ile çözme başarısız: {sonuc.get('hata')}")


def komut_chacha_avci(argumanlar: argparse.Namespace) -> None:
    # bellek dökümündeki durum matrislerini tarar.
    baslik_yaz("Bellek İçi ChaCha20 / Salsa20 Durum Matrisi Avcısı")
    if not os.path.exists(argumanlar.dosya):
        hata_yaz(f"Dosya bulunamadı: {argumanlar.dosya}")
        return
    with open(argumanlar.dosya, "rb") as f:
        veri = f.read(100 * 1024 * 1024)
    bulunanlar = chacha20_matris_ara(veri)
    if bulunanlar:
        basari_yaz(f"Toplam {len(bulunanlar)} adet ChaCha20 durum matrisi tespit edildi!")
        for b in bulunanlar:
            tablo_satiri_yaz(f"Ofset {hex(b['ofset'])}", f"Key: {b['anahtar_hex']}")
            tablo_satiri_yaz("  Nonce (IETF)", b["nonce_ietf_hex"])
    else:
        uyari_yaz("Bellek içinde ChaCha20 durum matrisi bulunamadı.")


def komut_canli_avci(argumanlar: argparse.Namespace) -> None:
    from rescat.analizciler.canli_surec_dondurucu import CanliSurecDondurucu
    baslik_yaz("Canlı Fidye Yazılımı Süreç Dondurucu ve Bellek Avcısı")
    if getattr(argumanlar, "tara", False) or not getattr(argumanlar, "pid", None):
        bilgi_yaz("Sistemde çalışan şüpheli fidye yazılımı süreçleri taranıyor...")
        supheliler = CanliSurecDondurucu.supheli_surecleri_tara()
        if supheliler:
            uyari_yaz(f"Toplam {len(supheliler)} adet şüpheli süreç tespit edildi:")
            for s in supheliler:
                tablo_satiri_yaz(f"PID: {s['pid']}", f"{s['ad']} -> {s['komut'][:60]}")
        else:
            basari_yaz("Çalışan şüpheli şifreleme süreci tespit edilmedi.")
        if not getattr(argumanlar, "pid", None):
            return

    pid = argumanlar.pid
    bilgi_yaz(f"PID {pid} süreci donduruluyor (SIGSTOP / Suspend)...")
    donduruldu = CanliSurecDondurucu.sureci_dondur(pid)
    if donduruldu:
        basari_yaz(f"PID {pid} başarıyla donduruldu! Şifreleme durduruldu.")
    else:
        uyari_yaz(f"PID {pid} dondurulamadı veya zaten durdurulmuş.")

    cikti_dokum = getattr(argumanlar, "dokum", None) or f"surec_{pid}_ram.raw"
    bilgi_yaz(f"Sürecin bellek dökümü alınıyor: {cikti_dokum}")
    dokuldu = CanliSurecDondurucu.surec_bellegini_dok(pid, cikti_dokum)
    if dokuldu:
        basari_yaz(f"Bellek dökümü başarıyla kaydedildi ({os.path.getsize(cikti_dokum)} bayt).")
        bilgi_yaz("Bellek içi kriptografik anahtarlar taranıyor...")
        from rescat.analizciler.bellek_anahtar_avcisi import bellek_dosyasini_tara
        sonuclar = bellek_dosyasini_tara(cikti_dokum)
        aes256 = sonuclar.get("dogrulanmis_aes256_anahtarlari", [])
        ch = sonuclar.get("chacha20_anahtarlari", [])
        xk = sonuclar.get("x25519_anahtarlari", [])
        if aes256:
            basari_yaz(f"Doğrulanmış AES-256 Anahtarları: {len(aes256)} adet")
            for k in aes256:
                tablo_satiri_yaz("AES-256 Key", k)
        if ch:
            basari_yaz(f"Doğrulanmış ChaCha20 Anahtarları: {len(ch)} adet")
            for c in ch:
                tablo_satiri_yaz("ChaCha20 Key", c.get("anahtar_hex"))
        if xk:
            basari_yaz(f"Doğrulanmış Curve25519 Anahtar Çiftleri: {len(xk)} adet")
            for x in xk:
                tablo_satiri_yaz("X25519 Priv", x.get("ozel_anahtar_hex"))
    else:
        hata_yaz("Süreç belleği okunamadı (root/yönetici yetkisi gerekebilir).")


def komut_vmdk_kurtar(argumanlar: argparse.Namespace) -> None:
    baslik_yaz("VMware ESXi Sanal Disk (.vmdk) Rekonstrüksiyonu")
    from rescat.cekirdek.yapisal_kurtarici import YapisalKurtarmaMotoru
    motor = YapisalKurtarmaMotoru(kuru_calistirma=argumanlar.kuru_calistirma, cikti_dizini=argumanlar.cikti)
    sonuc = motor.vmdk_disk_kurtar(argumanlar.dosya)
    if sonuc.get("basarili"):
        basari_yaz("VMDK sanal disk tanımlayıcısı (descriptor) başarıyla inşa edildi!")
        tablo_satiri_yaz("Hedef Descriptor", sonuc.get("hedef_yol"))
        tablo_satiri_yaz("Tespit Edilen FS", str(sonuc.get("tespit_edilen_fs")))
        tablo_satiri_yaz("Toplam Boyut", f"{sonuc.get('disk_boyutu_gb')} GB")
    else:
        hata_yaz(f"Kurtarma başarısız: {sonuc.get('hata')}")


def komut_crib_drag(argumanlar: argparse.Namespace) -> None:
    baslik_yaz("Otomatik Crib Dragging (Nonce Reuse Anahtarsız Çözüm)")
    from rescat.cekirdek.otomatik_crib_drag import OtomatikCribDragMotoru
    sonuc = OtomatikCribDragMotoru.dosyadan_anahtarsiz_coz(
        argumanlar.dosya1,
        argumanlar.dosya2
    )
    if sonuc.get("basarili"):
        basari_yaz(f"Keystream başarıyla çıkarıldı ({sonuc.get('keystream_boyutu')} bayt)!")
        tablo_satiri_yaz("1. Dosya Türü", str(sonuc.get("dosya1_tur")))
        tablo_satiri_yaz("2. Dosya Türü", str(sonuc.get("dosya2_tur")))
    else:
        hata_yaz(f"Crib-drag başarısız: {sonuc.get('hata')}")


def komut_aralikli(argumanlar: argparse.Namespace) -> None:
    baslik_yaz("Aralıklı / Kısmi (Intermittent) Şifreleme Analiz ve Çözücü")
    from rescat.cekirdek.aralikli_sifre_motoru import AralikliSifreMotoru
    motor = AralikliSifreMotoru(kuru_calistirma=argumanlar.kuru_calistirma, hedef_cikti_dizini=argumanlar.cikti)
    patern = motor.aralikli_patern_tespit_et(argumanlar.dosya)
    if patern.get("aralikli_mi"):
        uyari_yaz(f"Aralıklı şifreleme tespit edildi! Şifreli oran: %{patern.get('sifreli_oran', 0)*100:.1f}")
        tablo_satiri_yaz("Tahmini Şifreli Adım", f"{patern.get('tahmini_sifreli_adim')} bayt")
        tablo_satiri_yaz("Tahmini Atlama Adımı", f"{patern.get('tahmini_atlama_adim')} bayt")
        if getattr(argumanlar, "parcalari_cikar", False):
            cikti = getattr(argumanlar, "cikti", None) or "kurtarilan_dilimler"
            bilgi_yaz(f"Açık metin sektörleri çıkarılıyor -> {cikti}")
            k_sonuc = motor.acik_metin_dilimlerini_kurtar(argumanlar.dosya, cikti)
            basari_yaz(f"Toplam {k_sonuc.get('kurtarilan_parca_sayisi')} açık metin bloğu kurtarıldı!")
    else:
        bilgi_yaz(f"Dosya aralıklı şifreleme içermiyor ({patern.get('tur', 'bilinmiyor')}).")


def komut_adli_kurtar(argumanlar: argparse.Namespace) -> None:
    baslik_yaz("Adli Bilişim Kurtarma Motoru (Gölge Kopya / Snapshot / WAL / Geçici Ofis)")
    from rescat.analizciler.adli_kurtarma import AdliKurtarmaMotoru
    motor = AdliKurtarmaMotoru(cikti_dizini=getattr(argumanlar, "cikti", None))
    sonuc = motor.tam_adli_kurtarma_yurut(argumanlar.hedef)
    tablo_satiri_yaz("Hedef", sonuc["hedef"])
    tablo_satiri_yaz("Çıktı Dizini", sonuc["cikti_dizini"])
    tablo_satiri_yaz("Snapshot / Gölge Kopya", str(len(sonuc["snapshot_ve_golgeler"])))
    tablo_satiri_yaz("Geçici Ofis Artıkları", str(len(sonuc["gecici_ofis_artiklari"])))
    tablo_satiri_yaz("SQLite WAL/Journal", str(len(sonuc["sqlite_loglari"])))
    tablo_satiri_yaz("Toplam Kurtarılabilir Öğe", str(sonuc["toplam_kurtarilabilir_oge"]))
    if sonuc["toplam_kurtarilabilir_oge"] > 0:
        basari_yaz(f"Adli kurtarma tamamlandı. Kurtarılan öğeler incelenebilir -> {sonuc['cikti_dizini']}")
    else:
        uyari_yaz("Hedef için ilişkili gölge kopya veya geçici dosya artığı bulunamadı.")




def ana_calistirici() -> None:
    # windows çoklu işlem desteği.
    multiprocessing.freeze_support()

    # argüman ayrıştırıcıyı tanımlar ve programı başlatır.
    ayristirici = argparse.ArgumentParser(
        prog="rescat",
        description="rescat: Şifreli Dosya Tespiti, Algoritma Belirleme ve Doğrudan Çözüm Motoru (Windows & Linux Destekli)"
    )
    alt_komutlar = ayristirici.add_subparsers(dest="komut", help="çalıştırılacak alt komut")

    # 1. genel-tarama komutu.
    komut_genel_ayristirici = alt_komutlar.add_parser("genel-tarama", aliases=["tara"], help="ortam ve dizin genelinde otomatik tarama, analiz ve şifre çözümü")
    komut_genel_ayristirici.add_argument("hedef", nargs="?", default=".", help="taranacak vaka dizini (varsayılan: mevcut dizin)")
    komut_genel_ayristirici.add_argument("--derin", action="store_true", help="tüm alt dizinlerde derin örnekleme yap")
    komut_genel_ayristirici.add_argument("--cikti", help="raporların ve çıktı dosyalarının kaydedileceği dizin")
    komut_genel_ayristirici.add_argument("--kuru-calistirma", action="store_true", help="diske yazmadan test et")
    komut_genel_ayristirici.add_argument("--yedeksiz", action="store_true", help=".bak yedeği almadan çöz")
    komut_genel_ayristirici.add_argument("--rapor", help="tarama özetini kaydedecek rapor dosyası (.json)")

    # 2. ozel-tarama komutu.
    komut_ozel_ayristirici = alt_komutlar.add_parser("ozel-tarama", aliases=["ozel"], help="belirli dosya veya uzantıya odaklı derinlemesine analiz ve şifre çözümü")
    komut_ozel_ayristirici.add_argument("hedef", help="analiz edilecek dosya veya dizin")
    komut_ozel_ayristirici.add_argument("--uzanti", help="yalnızca belirtilen uzantıya sahip dosyaları incele (örnek: .locked)")
    komut_ozel_ayristirici.add_argument("--cikti", help="raporların ve çıktı dosyalarının kaydedileceği dizin")
    komut_ozel_ayristirici.add_argument("--kuru-calistirma", action="store_true", help="diske yazmadan test et")
    komut_ozel_ayristirici.add_argument("--yedeksiz", action="store_true", help=".bak yedeği almadan çöz")
    komut_ozel_ayristirici.add_argument("--entropi", type=float, default=7.2, help="özel entropi eşik değeri (varsayılan: 7.2)")
    komut_ozel_ayristirici.add_argument("--rapor", help="analiz raporu çıktı dosyası (.json)")

    # 3. analiz komutu.
    komut_analiz_ayristirici = alt_komutlar.add_parser("analiz", help="vaka dizini veya tekil dosya için derin kriptografik analiz")
    komut_analiz_ayristirici.add_argument("hedef", help="analiz edilecek dosya veya dizin")
    komut_analiz_ayristirici.add_argument("--rapor", help="rapor çıktı dosyası (.json, .md veya .html)")
    komut_analiz_ayristirici.add_argument("--stix-rapor", help="OASIS STIX 2.1 JSON adli olay raporu çıktı dosyası")
    komut_analiz_ayristirici.add_argument("--coz", action="store_true", help="analiz sonrasında otomatik çözüm aşamasına geç")

    # 4. kpa komutu.
    komut_kpa_ayristirici = alt_komutlar.add_parser("kpa", help="bilinen düz metin saldırısı ile anahtar tespiti")
    komut_kpa_ayristirici.add_argument("--orijinal", required=True, help="şifrelenmemiş orijinal dosya")
    komut_kpa_ayristirici.add_argument("--sifreli", required=True, help="şifrelenmiş dosya")

    # 5. avci komutu.
    komut_avci_ayristirici = alt_komutlar.add_parser("avci", help="bellek ve dosya içinden aes, salsa20, chacha20, tea, rc4 ve rsa anahtarı arama")
    komut_avci_ayristirici.add_argument("dosya", help="taranacak bellek dökümü veya dosya")

    # 6. zaman-kirici komutu.
    komut_zaman_ayristirici = alt_komutlar.add_parser("zaman-kirici", help="zaman tabanlı tohum ve xor anahtarı kırıcı")
    komut_zaman_ayristirici.add_argument("dosya", help="sifreli dosya")
    komut_zaman_ayristirici.add_argument("--zaman", type=int, help="merkez epoch zamanı (varsayılan: dosya değişiklik zamanı)")
    komut_zaman_ayristirici.add_argument("--aralik", type=int, default=3600, help="aranacak saniye aralığı (+/- saniye)")
    komut_zaman_ayristirici.add_argument("--uzunluk", type=int, default=16, help="anahtar uzunluğu bayt cinsinden (varsayılan: 16)")
    komut_zaman_ayristirici.add_argument("--format", help="beklenen format uzantısı (örnek: pdf, png, zip)")

    # 5. zayif-rsa komutu.
    komut_rsa_ayristirici = alt_komutlar.add_parser("zayif-rsa", help="zayıf rsa çarpanlara ayırma (fermat ve wiener)")
    komut_rsa_ayristirici.add_argument("--yontem", choices=["fermat", "wiener"], required=True, help="saldırı algoritması")
    komut_rsa_ayristirici.add_argument("-n", type=int, required=True, help="modül n tamsayısı")
    komut_rsa_ayristirici.add_argument("-e", type=int, default=65537, help="genel üs e (varsayılan: 65537)")
    komut_rsa_ayristirici.add_argument("--adim", type=int, default=1000000, help="fermat için maksimum arama adımı")
    komut_rsa_ayristirici.add_argument("--cikti", help="kurtarılan özel anahtarın kaydedileceği pem dosya yolu")

    # 6. onar komutu.
    komut_onar_ayristirici = alt_komutlar.add_parser("onar", help="hasarlı veya kısmi şifreli dosya başlığını onar")
    komut_onar_ayristirici.add_argument("dosya", help="hasarlı dosya yolu")
    komut_onar_ayristirici.add_argument("--format", required=True, help="hedef format (sqlite, png, pdf, zip, docx, xlsx, jpg, mp4)")
    komut_onar_ayristirici.add_argument("--cikti", help="onarılan çıktı dosyası")
    komut_onar_ayristirici.add_argument("--ezilen-boyut", type=int, help="ezilen bayt boyutu")

    # 7. interaktif komutu.
    alt_komutlar.add_parser("interaktif", help="adım adım terminal rehber sihirbazı")

    # 8. coz komutu.
    komut_coz_ayristirici = alt_komutlar.add_parser("coz", help="şifreli dosya veya dizinleri çözme (otomatik tespit ve çözüm)")
    komut_coz_ayristirici.add_argument("hedef", help="çözülecek dosya veya dizin")
    komut_coz_ayristirici.add_argument(
        "--algoritma",
        choices=[
            "aes", "poly1305", "xor", "chacha", "salsa20", "rc4", "tea", "xtea", "xxtea",
            "twofish", "blowfish", "3des", "camellia", "cast5", "idea",
            "seed", "sm4", "openssl", "rsa"
        ],
        required=False,
        help="şifreleme algoritması (belirtilmezse otomatik tespit edilir)"
    )
    komut_coz_ayristirici.add_argument("--anahtar", required=False, help="anahtar (belirtilmezse otomatik kırılır)")
    komut_coz_ayristirici.add_argument("--hex", action="store_true", help="anahtarın onaltılık (hex) formatta olduğunu belirtir")
    komut_coz_ayristirici.add_argument("--mod", default="cbc", choices=["cbc", "ctr", "ecb", "cfb", "ofb", "gcm"], help="blok şifreleyici çalışma modu")
    komut_coz_ayristirici.add_argument("--iv", help="başlatma vektörü (iv) dosya başında değilse")
    komut_coz_ayristirici.add_argument("--iv-harici", action="store_true", help="iv dosyanın başında yer almıyorsa")
    komut_coz_ayristirici.add_argument("--kaydirmali", action="store_true", help="xor için kaydırmalı mod")
    komut_coz_ayristirici.add_argument("--rsa-dolgu", default="oaep", choices=["oaep", "pkcs1"], help="rsa dolgu türü")
    komut_coz_ayristirici.add_argument("--uzanti", help="yalnızca belirli uzantıya sahip dosyaları çöz (örnek: .locked)")
    komut_coz_ayristirici.add_argument("--cikti", help="çözülen dosyaları farklı dizine kaydet")
    komut_coz_ayristirici.add_argument("--yedeksiz", action="store_true", help=".bak yedeği almadan çöz")
    komut_coz_ayristirici.add_argument("--kuru-calistirma", action="store_true", help="diske yazmadan test et")
    komut_coz_ayristirici.add_argument("--paralel", type=int, help="dizini paralel çözerken kullanılacak çekirdek sayısı")
    komut_coz_ayristirici.add_argument("--akici", action="store_true", help="büyük dosyalar için bellek tasarruflu akışkan mod")

    # 9. otonom komutu.
    komut_otonom_ayristirici = alt_komutlar.add_parser("otonom", help="harici müdahale gerektirmeyen tam otonom kurtarma ve analiz")
    komut_otonom_ayristirici.add_argument("hedef", nargs="?", default=None, help="taranacak ve kurtarılacak hedef dizin (varsayılan: mevcut dizin)")
    komut_otonom_ayristirici.add_argument("--cikti", help="raporların ve çıktı dosyalarının kaydedileceği dizin")
    komut_otonom_ayristirici.add_argument("--kuru-calistirma", action="store_true", help="diske yazmadan test et")
    komut_otonom_ayristirici.add_argument("--yedeksiz", action="store_true", help=".bak yedeği almadan çöz")

    # 10. yapisal-kurtar komutu.
    komut_yapisal_ayristirici = alt_komutlar.add_parser("yapisal-kurtar", help="kısmi şifreli zip, sqlite, pdf, mp4 ve jpeg yapısal kurtarma")
    komut_yapisal_ayristirici.add_argument("dosya", help="kurtarılacak dosya yolu")
    komut_yapisal_ayristirici.add_argument(
        "--format",
        choices=["zip", "sqlite", "pdf", "mp4", "jpeg", "otonom"],
        default="otonom",
        help="dosya yapısı"
    )
    komut_yapisal_ayristirici.add_argument("--cikti", help="kurtarılan dosya çıktı yolu")
    komut_yapisal_ayristirici.add_argument("--kuru-calistirma", action="store_true", help="diske yazmadan test et")

    # 11. keystream komutu.
    komut_keystream_ayristirici = alt_komutlar.add_parser("keystream", help="akış şifreleyici nonce tekrarı saldırısı ile anahtarsız çözüm")
    komut_keystream_ayristirici.add_argument("--referans-orj", required=True, help="bilinen orijinal referans dosya")
    komut_keystream_ayristirici.add_argument("--referans-sifreli", required=True, help="orijinalin şifreli karşılığı")
    komut_keystream_ayristirici.add_argument("--hedef", required=True, help="aynı anahtar akışı ile şifrelenmiş hedef dosya veya dizin")
    komut_keystream_ayristirici.add_argument("--yedeksiz", action="store_true", help=".bak yedeği almadan çöz")
    komut_keystream_ayristirici.add_argument("--kuru-calistirma", action="store_true", help="diske yazmadan test et")

    # 12. chacha-avci komutu.
    komut_chacha_ayristirici = alt_komutlar.add_parser("chacha-avci", help="bellek dökümünden chacha20 durum matrisi ve anahtar arama")
    komut_chacha_ayristirici.add_argument("dosya", help="taranacak bellek dökümü dosyası")

    # 13. canli-avci komutu.
    komut_canli_ayristirici = alt_komutlar.add_parser("canli-avci", help="çalışan fidye yazılımını anında dondur (SIGSTOP) ve bellekten anahtarı çek")
    komut_canli_ayristirici.add_argument("--pid", type=int, help="dondurulacak ve belleği alınacak hedef süreç kimliği (PID)")
    komut_canli_ayristirici.add_argument("--tara", action="store_true", help="çalışan şüpheli süreçleri tara")
    komut_canli_ayristirici.add_argument("--dokum", help="bellek dökümünün kaydedileceği dosya yolu")

    # 14. vmdk-kurtar komutu.
    komut_vmdk_ayristirici = alt_komutlar.add_parser("vmdk-kurtar", help="esxi sanal disk (.vmdk) tanımlayıcı ve bölüntü onarımı")
    komut_vmdk_ayristirici.add_argument("dosya", help="onarılacak flat.vmdk veya vmdk dosyası")
    komut_vmdk_ayristirici.add_argument("--cikti", help="yeni tanımlayıcı dosyasının kaydedileceği dizin")
    komut_vmdk_ayristirici.add_argument("--kuru-calistirma", action="store_true", help="diske yazmadan test et")

    # 15. crib-drag komutu.
    komut_crib_ayristirici = alt_komutlar.add_parser("crib-drag", help="nonce tekrarı durumunda iki şifreli dosyadan anahtarsız düz metin çözümü")
    komut_crib_ayristirici.add_argument("dosya1", help="1. şifreli dosya")
    komut_crib_ayristirici.add_argument("dosya2", help="2. şifreli dosya")

    # 16. aralikli komutu.
    komut_aralikli_ayristirici = alt_komutlar.add_parser("aralikli", help="aralıklı ve kısmi şifreleme analizi ile sağlam blok kurtarma")
    komut_aralikli_ayristirici.add_argument("dosya", help="analiz edilecek veya kurtarılacak dosya")
    komut_aralikli_ayristirici.add_argument("--parcalari-cikar", action="store_true", help="şifrelenmemiş açık metin dilimlerini diske çıkar")
    komut_aralikli_ayristirici.add_argument("--cikti", help="kurtarılan parçaların yazılacağı dizin")
    komut_aralikli_ayristirici.add_argument("--kuru-calistirma", action="store_true", help="diske yazmadan test et")

    # 17. adli-kurtar komutu.
    komut_adli_ayristirici = alt_komutlar.add_parser("adli-kurtar", help="gölge kopyalar (VSS/Snapshot), SQLite WAL ve geçici ofis artıklarını tarayıp kurtarma")
    komut_adli_ayristirici.add_argument("hedef", help="taranacak hedef dosya veya dizin")
    komut_adli_ayristirici.add_argument("--cikti", "-o", help="kurtarılan öğelerin yazılacağı dizin")

    if len(sys.argv) == 1:
        # argümansız başlatıldığında terminal sihirbazını açar.
        try:
            interaktif_sihirbaz_baslat()
            sys.exit(0)
        except (KeyboardInterrupt, EOFError):
            print("\n")
            sys.exit(0)

    # doğrudan dosya veya dizin yolu girildiyse otonom başlar.
    if len(sys.argv) == 2 and not sys.argv[1].startswith("-"):
        olasi_hedef = sys.argv[1]
        bilinen_komutlar = set(alt_komutlar.choices.keys())
        if olasi_hedef not in bilinen_komutlar and os.path.exists(olasi_hedef):
            motor = OtonomKurtarmaMotoru(hedef=olasi_hedef)
            motor.calistir()
            sys.exit(0)

    banner_yazdir()
    argumanlar = ayristirici.parse_args()

    if argumanlar.komut in ("genel-tarama", "tara"):
        komut_genel_tarama(argumanlar)
    elif argumanlar.komut in ("ozel-tarama", "ozel"):
        komut_ozel_tarama(argumanlar)
    elif argumanlar.komut == "otonom":
        komut_otonom(argumanlar)
    elif argumanlar.komut == "analiz":
        komut_analiz(argumanlar)
    elif argumanlar.komut == "kpa":
        komut_kpa(argumanlar)
    elif argumanlar.komut == "avci":
        komut_avci(argumanlar)
    elif argumanlar.komut == "zaman-kirici":
        komut_zaman_kirici(argumanlar)
    elif argumanlar.komut == "zayif-rsa":
        komut_zayif_rsa(argumanlar)
    elif argumanlar.komut == "onar":
        komut_onar(argumanlar)
    elif argumanlar.komut == "interaktif":
        interaktif_sihirbaz_baslat()
    elif argumanlar.komut == "coz":
        komut_coz(argumanlar)
    elif argumanlar.komut == "yapisal-kurtar":
        komut_yapisal_kurtar(argumanlar)
    elif argumanlar.komut == "keystream":
        komut_keystream(argumanlar)
    elif argumanlar.komut == "chacha-avci":
        komut_chacha_avci(argumanlar)
    elif argumanlar.komut == "canli-avci":
        komut_canli_avci(argumanlar)
    elif argumanlar.komut == "vmdk-kurtar":
        komut_vmdk_kurtar(argumanlar)
    elif argumanlar.komut == "crib-drag":
        komut_crib_drag(argumanlar)
    elif argumanlar.komut == "aralikli":
        komut_aralikli(argumanlar)
    elif argumanlar.komut == "adli-kurtar":
        komut_adli_kurtar(argumanlar)
    else:
        ayristirici.print_help()


if __name__ == "__main__":
    ana_calistirici()
