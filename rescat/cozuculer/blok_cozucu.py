from typing import Optional, Dict, Any, Type
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from rescat.cozuculer.temel_cozucu import TemelCozucu

DESTEKLENEN_BLOK_ALGORITMALARI: Dict[str, Dict[str, Any]] = {
    "blowfish": {
        "sinif": algorithms.Blowfish,
        "blok_boyutu": 8,
        "gecerli_anahtar_uzunluklari": range(4, 57),  # 32 ile 448 bit arası anahtar.
    },
    "3des": {
        "sinif": algorithms.TripleDES,
        "blok_boyutu": 8,
        "gecerli_anahtar_uzunluklari": (16, 24),
    },
    "tripledes": {
        "sinif": algorithms.TripleDES,
        "blok_boyutu": 8,
        "gecerli_anahtar_uzunluklari": (16, 24),
    },
    "cast5": {
        "sinif": algorithms.CAST5,
        "blok_boyutu": 8,
        "gecerli_anahtar_uzunluklari": range(5, 17),  # 40 ile 128 bit arası anahtar.
    },
    "cast": {
        "sinif": algorithms.CAST5,
        "blok_boyutu": 8,
        "gecerli_anahtar_uzunluklari": range(5, 17),
    },
    "camellia": {
        "sinif": algorithms.Camellia,
        "blok_boyutu": 16,
        "gecerli_anahtar_uzunluklari": (16, 24, 32),
    },
    "idea": {
        "sinif": algorithms.IDEA,
        "blok_boyutu": 8,
        "gecerli_anahtar_uzunluklari": (16,),
    },
    "seed": {
        "sinif": algorithms.SEED,
        "blok_boyutu": 16,
        "gecerli_anahtar_uzunluklari": (16,),
    },
    "sm4": {
        "sinif": algorithms.SM4,
        "blok_boyutu": 16,
        "gecerli_anahtar_uzunluklari": (16,),
    }
}


class BlokCozucu(TemelCozucu):
    # çoklu blok şifre çözücü sınıfı.
    def __init__(
        self,
        algoritma_adi: str,
        anahtar_baytlari: bytes,
        mod_adi: str = "cbc",
        baslatma_vektoru: Optional[bytes] = None,
        iv_dosya_basinda_mi: bool = True,
        dolgu_var_mi: bool = True,
        kuru_calistirma: bool = False,
        yedek_al: bool = True,
        hedef_cikti_dizini: Optional[str] = None
    ) -> None:
        super().__init__(
            kuru_calistirma=kuru_calistirma,
            yedek_al=yedek_al,
            hedef_cikti_dizini=hedef_cikti_dizini
        )
        self.algoritma_adi: str = algoritma_adi.lower().replace("-", "").replace("_", "")
        if self.algoritma_adi not in DESTEKLENEN_BLOK_ALGORITMALARI:
            raise ValueError(f"Desteklenmeyen blok algoritmasi: {algoritma_adi}. Desteklenenler: {list(DESTEKLENEN_BLOK_ALGORITMALARI.keys())}")

        self.ayar = DESTEKLENEN_BLOK_ALGORITMALARI[self.algoritma_adi]
        self.blok_boyutu = self.ayar["blok_boyutu"]
        self.anahtar_baytlari: bytes = anahtar_baytlari
        self.mod_adi: str = mod_adi.lower()
        self.baslatma_vektoru: Optional[bytes] = baslatma_vektoru
        self.iv_dosya_basinda_mi: bool = iv_dosya_basinda_mi
        self.dolgu_var_mi: bool = dolgu_var_mi

        # anahtar uzunluğu denetimi.
        gecerli_u = self.ayar["gecerli_anahtar_uzunluklari"]
        if isinstance(gecerli_u, tuple) and len(self.anahtar_baytlari) not in gecerli_u:
            # en yakın geçerli uzunluğa ayarlar.
            en_yakin = min(gecerli_u, key=lambda x: abs(x - len(self.anahtar_baytlari)))
            if len(self.anahtar_baytlari) < en_yakin:
                self.anahtar_baytlari = self.anahtar_baytlari.ljust(en_yakin, b"\x00")
            else:
                self.anahtar_baytlari = self.anahtar_baytlari[:en_yakin]

    def baytlari_coz(self, sifreli_baytlar: bytes) -> bytes:
        if not sifreli_baytlar:
            return b""

        kullanilacak_iv = self.baslatma_vektoru
        aslinda_sifreli_veri = sifreli_baytlar

        if self.mod_adi in ("cbc", "ctr", "cfb", "ofb"):
            if kullanilacak_iv is None:
                if self.iv_dosya_basinda_mi and len(aslinda_sifreli_veri) >= self.blok_boyutu:
                    kullanilacak_iv = aslinda_sifreli_veri[:self.blok_boyutu]
                    aslinda_sifreli_veri = aslinda_sifreli_veri[self.blok_boyutu:]
                else:
                    kullanilacak_iv = b"\x00" * self.blok_boyutu

        # mod nesnesini seçer.
        if self.mod_adi == "cbc":
            mod_nesnesi = modes.CBC(kullanilacak_iv)
        elif self.mod_adi == "ctr":
            mod_nesnesi = modes.CTR(kullanilacak_iv)
        elif self.mod_adi == "ecb":
            mod_nesnesi = modes.ECB()
        elif self.mod_adi == "cfb":
            mod_nesnesi = modes.CFB(kullanilacak_iv)
        elif self.mod_adi == "ofb":
            mod_nesnesi = modes.OFB(kullanilacak_iv)
        else:
            mod_nesnesi = modes.CBC(kullanilacak_iv)

        algo_sinifi: Type = self.ayar["sinif"]
        algo_nesnesi = algo_sinifi(self.anahtar_baytlari)

        # blok boyutu katı kontrolü.
        if self.mod_adi in ("cbc", "ecb") and len(aslinda_sifreli_veri) % self.blok_boyutu != 0:
            kirpilacak = len(aslinda_sifreli_veri) % self.blok_boyutu
            aslinda_sifreli_veri = aslinda_sifreli_veri[:-kirpilacak]

        if not aslinda_sifreli_veri:
            return b""

        sifreleyici = Cipher(algo_nesnesi, mod_nesnesi, backend=default_backend())
        cozucu = sifreleyici.decryptor()
        ham_cozulen = cozucu.update(aslinda_sifreli_veri) + cozucu.finalize()

        # dolgu varsa kaldırır.
        if self.dolgu_var_mi and self.mod_adi in ("cbc", "ecb"):
            try:
                ayiklayici = padding.PKCS7(self.blok_boyutu * 8).unpadder()
                return ayiklayici.update(ham_cozulen) + ayiklayici.finalize()
            except Exception:
                # bozuk dolguda ham çözülen baytları döndürür.
                return ham_cozulen

        return ham_cozulen
