import unittest
import os
import shutil
import tempfile
import json
from rescat.yardimcilar.raporlayici import Raporlayici


class TestStixRaporlayici(unittest.TestCase):

    def setUp(self):
        self.gecici_dizin = tempfile.mkdtemp()
        self.raporcu = Raporlayici(vaka_adi="test_vaka_stix")

    def tearDown(self):
        if os.path.exists(self.gecici_dizin):
            shutil.rmtree(self.gecici_dizin)

    def test_stix_bundle_olusturma_ve_kaydetme(self):
        test_dosyasi = os.path.join(self.gecici_dizin, "kurban.docx.locked")
        with open(test_dosyasi, "wb") as f:
            f.write(b"SAMPLE_ENCRYPTED_PAYLOAD_FOR_STIX_ANALYSIS" * 10)

        self.raporcu.ozet_ekle({
            "Tespit Edilen Zararlı Ailesi": "LockBit 3.0",
            "Toplam Dosya": 1
        })
        self.raporcu.dosya_analizi_ekle({
            "dosya_yolu": test_dosyasi,
            "algoritma": "AES-256-CBC",
            "sifreli_mi": True
        })
        self.raporcu.fidye_notu_ekle({
            "dosya_yolu": os.path.join(self.gecici_dizin, "README.txt"),
            "bitcoin_cuzdanlari": ["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"],
            "monero_cuzdanlari": ["888tNkZrPN6JsEgekjMnABU4TBzc2Dt29EPAvkFxbANsAnJYPbb3iQ1YBRk1UXcdRsiKc9dhwMVgN5S9cQUiyoogDavup3H"],
            "tor_baglantilari": ["http://lockbitaptc2iq4atewz2ise62q63wfknh7e6lbszqrevgah7cx2yd.onion"]
        })

        stix_dosya_yolu = os.path.join(self.gecici_dizin, "adli_rapor.stix.json")
        self.raporcu.stix_olarak_kaydet(stix_dosya_yolu)

        self.assertTrue(os.path.exists(stix_dosya_yolu))

        with open(stix_dosya_yolu, "r", encoding="utf-8") as rf:
            bundle = json.load(rf)

        self.assertEqual(bundle.get("type"), "bundle")
        self.assertEqual(bundle.get("spec_version"), "2.1")
        self.assertTrue(len(bundle.get("objects", [])) >= 5)

        tipler = [obj["type"] for obj in bundle["objects"]]
        self.assertIn("identity", tipler)
        self.assertIn("malware", tipler)
        self.assertIn("indicator", tipler)
        self.assertIn("relationship", tipler)


if __name__ == "__main__":
    unittest.main()
