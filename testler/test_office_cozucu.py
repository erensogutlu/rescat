import unittest
import os
import tempfile
import shutil
from rescat.cozuculer.office_cozucu import OfficeCozucu


class TestOfficeCozucu(unittest.TestCase):
    def setUp(self) -> None:
        self.gecici_dizin = tempfile.mkdtemp()

    def tearDown(self) -> None:
        shutil.rmtree(self.gecici_dizin)

    def test_office_belgesi_tespiti(self) -> None:
        sahte_ole = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 200 + b"EncryptedPackage" + b"\x00" * 300
        self.assertTrue(OfficeCozucu.office_belgesi_mi(sahte_ole))

        duz_veri = b"Bu normal bir metin belgesidir"
        self.assertFalse(OfficeCozucu.office_belgesi_mi(duz_veri))

    def test_gecersiz_veri_cozumu(self) -> None:
        cozucu = OfficeCozucu(kuru_calistirma=True)
        sonuc = cozucu.baytlari_coz(b"rastgele veri")
        self.assertIsNone(sonuc)


if __name__ == "__main__":
    unittest.main()
