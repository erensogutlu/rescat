from typing import Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from rescat.cozuculer.temel_cozucu import TemelCozucu


class AesCozucu(TemelCozucu):
    # aes modlarında şifre çözücü sınıf.
    def __init__(
        self,
        anahtar_baytlari: bytes,
        mod_adi: str = "cbc",
        baslatma_vektoru: Optional[bytes] = None,
        iv_dosya_basinda_mi: bool = True,
        dolgu_var_mi: bool = True,
        kuru_calistirma: bool = False,
        yedek_al: bool = True,
        hedef_cikti_dizini: Optional[str] = None
    ) -> None:
        # aes çözücü parametrelerini başlatır.
        super().__init__(
            kuru_calistirma=kuru_calistirma,
            yedek_al=yedek_al,
            hedef_cikti_dizini=hedef_cikti_dizini
        )
        self.anahtar_baytlari: bytes = anahtar_baytlari
        self.mod_adi: str = mod_adi.lower()
        self.baslatma_vektoru: Optional[bytes] = baslatma_vektoru
        self.iv_dosya_basinda_mi: bool = iv_dosya_basinda_mi
        self.dolgu_var_mi: bool = dolgu_var_mi

        if len(self.anahtar_baytlari) not in (16, 24, 32):
            raise ValueError("aes anahtar uzunlugu 16, 24 veya 32 bayt olmalidir")

    def baytlari_coz(self, sifreli_baytlar: bytes) -> bytes:
        # verilen bayt dizisini aes algoritmasıyla çözer.
        kullanilacak_iv = self.baslatma_vektoru
        aslinda_sifreli_veri = sifreli_baytlar

        # özel başlık veya dosya yapısı kontrolü.
        for baslik_sihirli in (
            b"SAFE_TEST_AES256_GCM\n", b"SAFE_TEST_AES256_CBC\n", b"AES_GCM\n",
            b"DFIRTEST-AES256-GCM\x00", b"DFIRTEST-AES256-GCM\n",
            b"DFIRTEST-AES256-CBC\x00", b"DFIRTEST-AES256-CBC\n"
        ):
            if aslinda_sifreli_veri.startswith(baslik_sihirli):
                aslinda_sifreli_veri = aslinda_sifreli_veri[len(baslik_sihirli):]
                if b"GCM" in baslik_sihirli:
                    self.mod_adi = "gcm"
                break

        # gcm modu işleme.
        if self.mod_adi == "gcm":
            if kullanilacak_iv is not None and len(aslinda_sifreli_veri) >= 16:
                tag = aslinda_sifreli_veri[-16:]
                sifreli_govde = aslinda_sifreli_veri[:-16]
                try:
                    sifreleyici = Cipher(algorithms.AES(self.anahtar_baytlari), modes.GCM(kullanilacak_iv, tag), backend=default_backend())
                    cozucu = sifreleyici.decryptor()
                    return cozucu.update(sifreli_govde) + cozucu.finalize()
                except Exception:
                    pass

            for iv_len in (12, 16):
                if len(aslinda_sifreli_veri) >= iv_len + 16:
                    olasi_iv = aslinda_sifreli_veri[:iv_len]
                    olasi_tag = aslinda_sifreli_veri[-16:]
                    olasi_govde = aslinda_sifreli_veri[iv_len:-16]
                    try:
                        sifreleyici = Cipher(algorithms.AES(self.anahtar_baytlari), modes.GCM(olasi_iv, olasi_tag), backend=default_backend())
                        cozucu = sifreleyici.decryptor()
                        return cozucu.update(olasi_govde) + cozucu.finalize()
                    except Exception:
                        continue
            raise ValueError("AES-GCM desifreleme basarisiz oldu (gecersiz anahtar, IV veya tag).")

        # cbc veya ctr modunda iv dosya başından alınır.
        if self.mod_adi in ("cbc", "ctr"):
            if kullanilacak_iv is None and self.iv_dosya_basinda_mi:
                if len(sifreli_baytlar) < 16:
                    raise ValueError("veri boyutu iv icerecek kadar uzun degil")
                kullanilacak_iv = sifreli_baytlar[:16]
                aslinda_sifreli_veri = sifreli_baytlar[16:]
            elif kullanilacak_iv is None:
                # varsayılan sıfır iv kullanır.
                kullanilacak_iv = b"\x00" * 16

        # mod nesnesini hazırlar.
        if self.mod_adi == "cbc":
            sifre_modu = modes.CBC(kullanilacak_iv)
        elif self.mod_adi == "ctr":
            sifre_modu = modes.CTR(kullanilacak_iv)
        elif self.mod_adi == "ecb":
            sifre_modu = modes.ECB()
        else:
            raise ValueError(f"desteklenmeyen aes modu: {self.mod_adi}")

        sifreleyici = Cipher(
            algorithms.AES(self.anahtar_baytlari),
            sifre_modu,
            backend=default_backend()
        )
        cozucu_nesne = sifreleyici.decryptor()
        ham_cozulmus = cozucu_nesne.update(aslinda_sifreli_veri) + cozucu_nesne.finalize()

        # pkcs7 dolgusunu kaldırır.
        if self.dolgu_var_mi and self.mod_adi in ("cbc", "ecb"):
            try:
                dolgu_kaldirici = padding.PKCS7(128).unpadder()
                temiz_veri = dolgu_kaldirici.update(ham_cozulmus) + dolgu_kaldirici.finalize()
                return temiz_veri
            except Exception:
                # dolgu hatasında kurtarılan veriyi korur.
                return ham_cozulmus

        return ham_cozulmus
