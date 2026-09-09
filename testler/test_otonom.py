import os
import shutil
import tempfile
import unittest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from rescat.yardimcilar.konsol import banner_yazdir, bilgi_yaz, basari_yaz
from rescat.cozuculer.djvu_cozucu import DjvuCozucu
from rescat.cekirdek.djvu_veritabani import VARSAYILAN_OFFLINE_ANAHTAR_HEX
from rescat.otonom import OtonomKurtarmaMotoru


class TestOtonomVeCevrimdisi(unittest.TestCase):
    # otonom kurtarma ve sifre cozumu testleri

    def test_konsol_guvenligi(self) -> None:
        # banner ve konsol ciktilarinin hata firlatmadan guvenle calismasi
        try:
            banner_yazdir()
            bilgi_yaz("Test bilgi mesaji")
            basari_yaz("Test basari mesaji")
            konsol_calisti = True
        except Exception:
            konsol_calisti = False
        self.assertTrue(konsol_calisti)

    def test_djvu_offline_cozucu(self) -> None:
        # stop/djvu offline anahtariyla dosya cozme testi
        gecici_dizin = tempfile.mkdtemp()
        try:
            # sahte bir png dosyasi hazirla
            png_sihirli = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x10\x00\x00\x00\x10"
            govde = b"A" * 1024
            orijinal_veri = png_sihirli + govde

            # varsayilan stop offline anahtariyla ilk kismi sifrele
            anahtar = bytes.fromhex(VARSAYILAN_OFFLINE_ANAHTAR_HEX)
            iv = b"\x00" * 16

            sifrelenecek_blok = orijinal_veri[:16]
            sifreleyici = Cipher(algorithms.AES(anahtar), modes.CBC(iv), backend=default_backend()).encryptor()
            sifreli_blok = sifreleyici.update(sifrelenecek_blok) + sifreleyici.finalize()

            # stop/djvu kurban id'si ekle (offline t1)
            kurban_isaretcisi = b"abc123def456ghi789jkl012mno345pqrst1"
            sifreli_dosya_icerigi = sifreli_blok + orijinal_veri[16:] + kurban_isaretcisi

            test_dosya_yolu = os.path.join(gecici_dizin, "belge.png.gero")
            with open(test_dosya_yolu, "wb") as f:
                f.write(sifreli_dosya_icerigi)

            cozucu = DjvuCozucu(anahtar_baytlari=anahtar, yedek_al=True)
            sonuc = cozucu.tekil_dosya_coz(test_dosya_yolu)

            self.assertTrue(sonuc["basarili"])
            self.assertEqual(sonuc["dogrulanan_tur"], "png")
            self.assertIn("t1", sonuc.get("kurban_id", ""))

            # .bak yedegi kontrolu
            self.assertTrue(os.path.exists(test_dosya_yolu + ".bak"))

            # kurtarilan dosyanin basligini dogrula
            with open(test_dosya_yolu, "rb") as kurtarilan:
                kurtarilan_baslik = kurtarilan.read(8)
                self.assertEqual(kurtarilan_baslik, b"\x89PNG\r\n\x1a\n")

        finally:
            shutil.rmtree(gecici_dizin)

    def test_otonom_kurtarma_motoru_tam_dongu(self) -> None:
        # otonom motorun tum fazlarinin (kesif, bellek avi, cozme, raporlama) calismasi
        vaka_dizini = tempfile.mkdtemp()
        cikti_dizini = tempfile.mkdtemp()

        try:
            # 1. sahte bellek dokumu ve icine aes anahtari yerlestir
            aes_anahtar = b"0123456789abcdef0123456789abcdef"  # 32 bayt aes-256
            dmp_yolu = os.path.join(vaka_dizini, "memory.dmp")
            with open(dmp_yolu, "wb") as f:
                f.write(b"\x90" * 500 + aes_anahtar + b"\x90" * 500)

            # 2. aes ile sifrelenmis sahte bir pdf dosyasi olustur
            pdf_sihirli = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n"
            pdf_govde = b"Test PDF icerigi kripto kurtarma senaryosu" * 50
            pdf_orijinal = pdf_sihirli + pdf_govde

            # 16 bayt iv dosya basinda
            iv = b"1234567890123456"
            sifreleyici = Cipher(algorithms.AES(aes_anahtar), modes.CBC(iv), backend=default_backend()).encryptor()
            # dolgula
            pad_len = 16 - (len(pdf_orijinal) % 16)
            pdf_dolgulu = pdf_orijinal + bytes([pad_len] * pad_len)
            sifreli_pdf = iv + sifreleyici.update(pdf_dolgulu) + sifreleyici.finalize()

            sifreli_dosya = os.path.join(vaka_dizini, "onemli_belge.pdf.locked")
            with open(sifreli_dosya, "wb") as f:
                f.write(sifreli_pdf)

            # otonom motoru baslat
            motor = OtonomKurtarmaMotoru(
                hedef_dizin=vaka_dizini,
                cikti_dizini=cikti_dizini,
                kuru_calistirma=False,
                yedek_al=True,
                rapor_diske_kaydet=True
            )
            calisma_sonucu = motor.calistir()

            self.assertTrue(calisma_sonucu["basarili"])
            self.assertGreater(len(calisma_sonucu["bellek_dokumleri"]), 0)
            self.assertGreater(len(calisma_sonucu["sifreli_dosyalar"]), 0)

            # cozulen dosyalarin dogrulanmasi
            self.assertGreater(len(calisma_sonucu["cozulen_dosyalar"]), 0)
            self.assertTrue(os.path.exists(sifreli_dosya + ".bak"))
            with open(sifreli_dosya, "rb") as kurtarilan_dosya:
                self.assertEqual(kurtarilan_dosya.read(5), b"%PDF-")

            # raporlarin olustugunu dogrula
            raporlar = calisma_sonucu["raporlar"]
            self.assertTrue(os.path.exists(raporlar["json"]))
            self.assertTrue(os.path.exists(raporlar["markdown"]))
            self.assertTrue(os.path.exists(raporlar["html"]))

            # html raporu iceriginde svg ve bolumlerin yer aldigini kontrol et
            with open(raporlar["html"], "r", encoding="utf-8") as html_f:
                html_icerik = html_f.read()
                self.assertIn("rescat Ransomware Olay Mudahale Raporu", html_icerik)
                self.assertIn("Desifreleme Islemleri", html_icerik)

        finally:
            shutil.rmtree(vaka_dizini)
            shutil.rmtree(cikti_dizini)

    def test_otonom_kurtarma_chacha20_bellek(self) -> None:
        # ram dokumundeki chacha20 durum matrisi ile otonom kurtarma testi
        vaka_dizini = tempfile.mkdtemp()
        cikti_dizini = tempfile.mkdtemp()

        try:
            # 1. 64 baytlik chacha20 durum matrisi olustur
            anahtar = bytes([i % 256 for i in range(32)])  # 32 bayt cesitli anahtar
            sayac_ve_nonce = b"\x00\x00\x00\x00" + (b"\x77" * 12)  # 16 bayt
            matris = b"expand 32-byte k" + anahtar + sayac_ve_nonce

            dmp_yolu = os.path.join(vaka_dizini, "crashdump.raw")
            with open(dmp_yolu, "wb") as f:
                f.write(b"\x00" * 1000 + matris + b"\x00" * 1000)

            # 2. chacha20 ile sifrelenmis sahte png dosyasi olustur
            png_veri = b"\x89PNG\r\n\x1a\n" + b"ChaCha20 Otonom Test" * 20
            sifreleyici = Cipher(algorithms.ChaCha20(anahtar, sayac_ve_nonce), mode=None, backend=default_backend()).encryptor()
            sifreli_icerik = sifreleyici.update(png_veri) + sifreleyici.finalize()

            sifreli_dosya = os.path.join(vaka_dizini, "resim.png.enc")
            with open(sifreli_dosya, "wb") as f:
                f.write(sifreli_icerik)

            # 3. otonom motoru calistir
            motor = OtonomKurtarmaMotoru(
                hedef_dizin=vaka_dizini,
                cikti_dizini=cikti_dizini,
                kuru_calistirma=False,
                yedek_al=True
            )
            calisma_sonucu = motor.calistir()

            self.assertTrue(calisma_sonucu["basarili"])
            self.assertGreaterEqual(len(calisma_sonucu["cozulen_dosyalar"]), 1)
            with open(sifreli_dosya, "rb") as kurtarilan:
                self.assertEqual(kurtarilan.read(8), b"\x89PNG\r\n\x1a\n")
        finally:
            shutil.rmtree(vaka_dizini)
            shutil.rmtree(cikti_dizini)

    def test_otonom_varsayilan_parametreler(self) -> None:
        # motorun parametresiz olarak guvenle baslatilabilmesi
        motor = OtonomKurtarmaMotoru()
        self.assertTrue(os.path.isabs(motor.hedef_dizin))
        self.assertTrue(os.path.isabs(motor.cikti_dizini))
        self.assertFalse(motor.kuru_calistirma)
        self.assertTrue(motor.yedek_al)

    def test_otonom_kurtarma_zaman_tabanli_xor(self) -> None:
        # Zaman tabanli PRNG tohum ve XOR anahtar kirici ile otonom kurtarma
        import time
        from rescat.cekirdek.zaman_kirici import LcgRastgele

        vaka_dizini = tempfile.mkdtemp()
        cikti_dizini = tempfile.mkdtemp()

        try:
            tohum = int(time.time()) - 30  # 30 saniye once
            uretec = LcgRastgele(tohum)
            anahtar = uretec.rastgele_baytlar(16)

            orijinal_veri = b"%PDF-1.7\n" + b"Zaman tabanli XOR otonom kurtarma testi" * 10
            sifreli_icerik = bytearray(len(orijinal_veri))
            for i, b in enumerate(orijinal_veri):
                sifreli_icerik[i] = b ^ anahtar[i % 16]

            sifreli_dosya = os.path.join(vaka_dizini, "rapor.pdf.enc")
            with open(sifreli_dosya, "wb") as f:
                f.write(sifreli_icerik)

            # dosyanin mtime zaman damgasini tohum zamanina ayarla
            os.utime(sifreli_dosya, (tohum, tohum))

            motor = OtonomKurtarmaMotoru(
                hedef_dizin=vaka_dizini,
                cikti_dizini=cikti_dizini,
                kuru_calistirma=False,
                yedek_al=True
            )
            calisma_sonucu = motor.calistir()

            self.assertTrue(calisma_sonucu["basarili"])
            self.assertGreaterEqual(len(calisma_sonucu["cozulen_dosyalar"]), 1)
            self.assertTrue(os.path.exists(sifreli_dosya + ".bak"))

            with open(sifreli_dosya, "rb") as f:
                kurtarilan_baslik = f.read(5)
                self.assertEqual(kurtarilan_baslik, b"%PDF-")
        finally:
            shutil.rmtree(vaka_dizini)
            shutil.rmtree(cikti_dizini)


if __name__ == "__main__":
    unittest.main()
