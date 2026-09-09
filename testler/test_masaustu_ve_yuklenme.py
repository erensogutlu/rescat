import os
import unittest
import tempfile
from rescat.yardimcilar.konsol import (
    masaustu_dizini_al,
    YuklenmeCubugu,
    sifre_cozme_animasyonu_oynat,
    dengeli_bekle
)
from rescat.yardimcilar.raporlayici import Raporlayici
from rescat.otonom import OtonomKurtarmaMotoru


class TestMasaustuVeYuklenme(unittest.TestCase):
    def test_masaustu_dizini_al(self) -> None:
        # Calisan isletim sisteminin masaustu dizininin dogru tespit edilmesi
        masaustu = masaustu_dizini_al()
        self.assertTrue(os.path.isabs(masaustu))
        self.assertTrue(os.path.isdir(masaustu))
        self.assertTrue("Desktop" in masaustu or "Masaüstü" in masaustu or "Masaustu" in masaustu)

    def test_yuklenme_cubugu_ve_animasyon(self) -> None:
        # Sifre cozme ilerleme cubugunun hatasiz calismasi
        cubuk = YuklenmeCubugu(toplam=10, baslik="Test Çözüm", dosya_adi="ornek.pdf.locked")
        self.assertEqual(cubuk.mevcut, 0)
        cubuk.guncelle(5, asama="Bloklar çözülüyor")
        self.assertEqual(cubuk.mevcut, 5)
        cubuk.animasyonlu_tamamla(hedef_dosya="ornek.pdf", basarili=True, detay="AES-256")
        self.assertTrue(cubuk._tamamlandi)

        # sifre_cozme_animasyonu_oynat cagrisi
        sifre_cozme_animasyonu_oynat("test_dosya.enc", algoritma="Twofish", adim_sayisi=3, gecikme=0.001)

    def test_dengeli_bekle(self) -> None:
        # Titremeyi onleyen dengeli bekle fonksiyonu
        dengeli_bekle(0.001)

    def test_raporlayici_konsolda_gosterim(self) -> None:
        # Raporun diske yazilmadan dogrudan konsolda sunulmasi
        rapor = Raporlayici(vaka_adi="test_vaka")
        rapor.ozet_ekle({"Toplam": 1, "Kurtarilan": 1})
        rapor.cozum_ekle({"dosya_yolu": "deneme.enc", "basarili": True, "algoritma": "AES", "dogrulanan_tur": "pdf"})
        rapor.fidye_notu_ekle({"dosya_yolu": "README.txt", "bitcoin_cuzdanlari": ["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"]})
        rapor.anahtar_ekle({"tur": "AES-256", "deger": "00" * 32, "kaynak": "RAM"})
        rapor.adli_analiz_ekle({"risk_seviyesi": "YUKSEK", "toplam_bulgu": 1, "bulgular": [{"mitre_id": "T1486", "mitre_ad": "Data Encrypted for Impact", "taktik": "Impact", "risk": "Kritik"}]})

        # konsolda_rapor_goster metodu istisna firlatmamali
        rapor.konsolda_rapor_goster()

    def test_otonom_varsayilan_diske_yazmama_ve_masaustu(self) -> None:
        # Otonom motor varsayilan olarak diske dosya yazmamali ve masaustune cikti vermelidir
        vaka_dizini = tempfile.mkdtemp()
        try:
            motor = OtonomKurtarmaMotoru(hedef_dizin=vaka_dizini)
            self.assertFalse(motor.rapor_diske_kaydet)
            self.assertEqual(motor.cikti_dizini, masaustu_dizini_al())

            # Calistiginda cikti dizininde kurtarma_raporu.* dosyalari olusmamali
            sonuc = motor.calistir()
            self.assertTrue(sonuc["basarili"])
            self.assertIn("konsolda_gosterildi", sonuc["raporlar"])

            # Cikti dizininde herhangi bir rapor dosyasi olmamali
            for ad in ["kurtarma_raporu.json", "kurtarma_raporu.md", "kurtarma_raporu.html"]:
                self.assertFalse(os.path.exists(os.path.join(vaka_dizini, ad)))
        finally:
            if os.path.exists(vaka_dizini):
                os.rmdir(vaka_dizini)


if __name__ == "__main__":
    unittest.main()
