import os
import tempfile
import unittest
from rescat.cekirdek.keystream_cozucu import KeystreamCozucu


class TestKeystreamCozucu(unittest.TestCase):
    """
    Stream cipher nonce reuse (keystream replay) saldirisi testleri.
    """

    def test_keystream_ile_anahtarsiz_cozme(self) -> None:
        # Sahte bir 256 baytlik Keystream (ornegin ChaCha20/AES-CTR tarafindan ayni nonce ile uretilmis)
        statik_keystream = os.urandom(256)

        # 1. Dosya (Kullanicinin elinde orijinali olan ornek dosya, ornegin bilinen bir PNG veya logo)
        dosya1_duz = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + b"LOGO_VERILERI_12345" * 8
        dosya1_sifreli = bytes(dosya1_duz[i] ^ statik_keystream[i] for i in range(len(dosya1_duz)))

        # 2. Dosya (Sifresi kurtarilmak istenen gizli kurban dosyasi, ornegin PDF)
        dosya2_duz = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n" + b"GIZLI_SIRKET_BILANCOSU_2026" * 3
        dosya2_sifreli = bytes(dosya2_duz[i] ^ statik_keystream[i] for i in range(len(dosya2_duz)))

        with tempfile.NamedTemporaryFile(delete=False) as f_d1_orj, \
             tempfile.NamedTemporaryFile(delete=False) as f_d1_sif, \
             tempfile.NamedTemporaryFile(delete=False) as f_d2_sif:

            f_d1_orj.write(dosya1_duz)
            f_d1_sif.write(dosya1_sifreli)
            f_d2_sif.write(dosya2_sifreli)

            yol_d1_orj = f_d1_orj.name
            yol_d1_sif = f_d1_sif.name
            yol_d2_sif = f_d2_sif.name

        cikti_d2 = yol_d2_sif + ".cozuldu"

        try:
            motor = KeystreamCozucu(kuru_calistirma=False, yedek_al=False)
            sonuc = motor.coklu_keystream_cozumu(
                referans_orijinal_dosya=yol_d1_orj,
                referans_sifreli_dosya=yol_d1_sif,
                hedef_dizin_veya_dosyalar=[yol_d2_sif]
            )

            self.assertTrue(sonuc["basarili"])
            self.assertEqual(sonuc["cozulen_toplam_dosya"], 1)

            # Dosya 2'nin anahtarsiz olarak %100 orijinal haline dondugunu dogrula!
            with open(cikti_d2, "rb") as f_res:
                cozulmus_veri = f_res.read()

            self.assertEqual(cozulmus_veri, dosya2_duz)
            self.assertTrue(cozulmus_veri.startswith(b"%PDF-1.7"))

        finally:
            for p in (yol_d1_orj, yol_d1_sif, yol_d2_sif, cikti_d2):
                if os.path.exists(p):
                    os.remove(p)


if __name__ == "__main__":
    unittest.main()
