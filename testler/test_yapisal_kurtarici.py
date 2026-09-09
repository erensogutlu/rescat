import os
import io
import tempfile
import zipfile
import unittest
from rescat.cekirdek.yapisal_kurtarici import YapisalKurtarmaMotoru


class TestYapisalKurtarici(unittest.TestCase):
    """
    Askeri standartta kismi sifrelenmis ZIP/DOCX, SQLite ve PDF dosyalarinin
    derin yapisal kurtarma testleri.
    """

    def test_kismi_sifreli_zip_kurtarma(self) -> None:
        # Gercek bir ZIP dosyasi olustur
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("baslik_dosyasi.txt", "Bu dosya dosya basinda yer aliyor." * 10)
            zf.writestr("onemli_not.txt", "Bu veri askeri standartta sifrelemeye ragmen kurtarilmalidir!" * 10)
            zf.writestr("veriler.csv", "id,isim,tutar\n1,Ahmet,5000\n2,Mehmet,12000\n" * 20)

        orijinal_zip_baytlari = zip_buffer.getvalue()

        # LockBit / BlackCat tarzi ilk 100 bayti AES-256 taklit ederek rastgele baytlarla ez
        ezilmis_kisim = os.urandom(100)
        hasarli_zip_baytlari = ezilmis_kisim + orijinal_zip_baytlari[100:]

        with tempfile.NamedTemporaryFile(delete=False, suffix=".docx") as temp_in:
            temp_in.write(hasarli_zip_baytlari)
            hasarli_yol = temp_in.name

        cikti_yol = hasarli_yol + ".kurtarildi.zip"

        try:
            motor = YapisalKurtarmaMotoru()
            sonuc = motor.zip_arsiv_kurtar(hasarli_yol, hedef_cikti=cikti_yol)

            self.assertTrue(sonuc["basarili"])
            self.assertGreaterEqual(sonuc["kurtarilan_ic_dosya_sayisi"], 1)

            # Kurtarilan zip'in gecerli ve acilabilir oldugunu dogrula
            with zipfile.ZipFile(cikti_yol, "r") as z_out:
                dosya_listesi = z_out.namelist()
                self.assertIn("veriler.csv", dosya_listesi)
                csv_icerik = z_out.read("veriler.csv").decode("utf-8")
                self.assertIn("Ahmet,5000", csv_icerik)

        finally:
            if os.path.exists(hasarli_yol):
                os.remove(hasarli_yol)
            if os.path.exists(cikti_yol):
                os.remove(cikti_yol)

    def test_sqlite_leaf_sayfa_kurtarma(self) -> None:
        # SQLite B-Tree Leaf Page takliti (0x0D ile baslayan sayfa ve icinde metinler)
        sayfa_1 = os.urandom(4096)  # Ilk sayfa (header) tamamen sifrelenmis
        sayfa_2 = bytearray(4096)
        sayfa_2[0] = 0x0D  # Leaf Table B-Tree Page Bayragi
        sayfa_2[1:3] = b"\x00\x00"
        sayfa_2[3:5] = b"\x00\x03"  # 3 hucre
        # Hucre icerisine sahte kayit verisi yaz
        gizli_veri = b"KURTARILAN_MUSTERI_KAYITLARI_TC12345678"
        sayfa_2[100:100 + len(gizli_veri)] = gizli_veri

        hasarli_db_verisi = sayfa_1 + bytes(sayfa_2)

        with tempfile.NamedTemporaryFile(delete=False, suffix=".sqlite") as temp_in:
            temp_in.write(hasarli_db_verisi)
            hasarli_yol = temp_in.name

        cikti_yol = hasarli_yol + ".kurtarildi.db"

        try:
            motor = YapisalKurtarmaMotoru()
            sonuc = motor.sqlite_yapraklari_kurtar(hasarli_yol, hedef_cikti=cikti_yol)

            self.assertTrue(sonuc["basarili"])
            self.assertGreaterEqual(sonuc["kurtarilan_leaf_sayfa_sayisi"], 1)
            self.assertGreaterEqual(sonuc["cikartilan_metin_kayit_sayisi"], 1)

            # Ilk 100 baytin onarildigini dogrula
            with open(cikti_yol, "rb") as f_out:
                baslik = f_out.read(16)
            self.assertEqual(baslik, b"SQLite format 3\x00")

        finally:
            if os.path.exists(hasarli_yol):
                os.remove(hasarli_yol)
            if os.path.exists(cikti_yol):
                os.remove(cikti_yol)


if __name__ == "__main__":
    unittest.main()
