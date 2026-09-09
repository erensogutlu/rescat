import os
import shutil
from typing import Dict, Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from rescat.cozuculer.temel_cozucu import TemelCozucu


class AkiciCozucu(TemelCozucu):
    # büyük dosyaları bellek tüketmeden akışkan çözen sınıf.
    def __init__(
        self,
        anahtar_baytlari: bytes,
        algoritma_adi: str = "aes",
        mod_adi: str = "ctr",
        baslatma_vektoru: Optional[bytes] = None,
        tampon_boyutu: int = 1024 * 1024,  # 1 mb tampon boyutu.
        kuru_calistirma: bool = False,
        yedek_al: bool = True,
        hedef_cikti_dizini: Optional[str] = None
    ) -> None:
        # akıcı çözücü yapılandırmasını tanımlar.
        super().__init__(
            kuru_calistirma=kuru_calistirma,
            yedek_al=yedek_al,
            hedef_cikti_dizini=hedef_cikti_dizini
        )
        self.anahtar_baytlari: bytes = anahtar_baytlari
        self.algoritma_adi: str = algoritma_adi.lower()
        self.mod_adi: str = mod_adi.lower()
        self.baslatma_vektoru: bytes = baslatma_vektoru or (b"\x00" * 16)
        self.tampon_boyutu: int = tampon_boyutu

    def baytlari_coz(self, sifreli_baytlar: bytes) -> bytes:
        # bellek içi çözme yöntemi.
        if self.algoritma_adi == "xor":
            uzunluk = len(self.anahtar_baytlari)
            return bytes(b ^ self.anahtar_baytlari[i % uzunluk] for i, b in enumerate(sifreli_baytlar))
        else:
            sifre_modu = modes.CTR(self.baslatma_vektoru) if self.mod_adi == "ctr" else modes.CBC(self.baslatma_vektoru)
            sifreleyici = Cipher(algorithms.AES(self.anahtar_baytlari), sifre_modu, backend=default_backend()).decryptor()
            return sifreleyici.update(sifreli_baytlar) + sifreleyici.finalize()

    def akiskan_dosya_coz(self, kaynak_dosya_yolu: str) -> Dict[str, any]:
        # dosyayı diske akışkan olarak yazar.
        if not os.path.exists(kaynak_dosya_yolu):
            return {"basarili": False, "hata": "dosya bulunamadi"}

        dosya_boyutu = os.path.getsize(kaynak_dosya_yolu)

        if self.hedef_cikti_dizini:
            os.makedirs(self.hedef_cikti_dizini, exist_ok=True)
            hedef_dosya_yolu = os.path.join(self.hedef_cikti_dizini, os.path.basename(kaynak_dosya_yolu))
        else:
            hedef_dosya_yolu = kaynak_dosya_yolu + ".cozuldu"

        if self.yedek_al and not self.hedef_cikti_dizini:
            shutil.copy2(kaynak_dosya_yolu, kaynak_dosya_yolu + ".bak")

        from rescat.yardimcilar.konsol import YuklenmeCubugu
        cubuk = YuklenmeCubugu(toplam=max(1, dosya_boyutu), baslik="Akıcı Şifre Çözülüyor", dosya_adi=kaynak_dosya_yolu)
        try:
            toplam_islenen = 0
            if self.algoritma_adi == "xor":
                anahtar_uzunlugu = len(self.anahtar_baytlari)
                with open(kaynak_dosya_yolu, "rb") as giris_akisi, open(hedef_dosya_yolu, "wb") as cikis_akisi:
                    while True:
                        parca = giris_akisi.read(self.tampon_boyutu)
                        if not parca:
                            break
                        cozulmus_parca = bytearray(len(parca))
                        for i, bayt in enumerate(parca):
                            cozulmus_parca[i] = bayt ^ self.anahtar_baytlari[(toplam_islenen + i) % anahtar_uzunlugu]
                        cikis_akisi.write(cozulmus_parca)
                        toplam_islenen += len(parca)
                        cubuk.guncelle(toplam_islenen, asama=f"{toplam_islenen / (1024*1024):.1f} MB")
            else:
                # aes akışı.
                sifre_modu = modes.CTR(self.baslatma_vektoru) if self.mod_adi == "ctr" else modes.CBC(self.baslatma_vektoru)
                cozucu_nesne = Cipher(algorithms.AES(self.anahtar_baytlari), sifre_modu, backend=default_backend()).decryptor()

                with open(kaynak_dosya_yolu, "rb") as giris_akisi, open(hedef_dosya_yolu, "wb") as cikis_akisi:
                    while True:
                        parca = giris_akisi.read(self.tampon_boyutu)
                        if not parca:
                            break
                        cozulmus_parca = cozucu_nesne.update(parca)
                        cikis_akisi.write(cozulmus_parca)
                        toplam_islenen += len(parca)
                        cubuk.guncelle(toplam_islenen, asama=f"{toplam_islenen / (1024*1024):.1f} MB")
                    cikis_akisi.write(cozucu_nesne.finalize())

            cubuk.animasyonlu_tamamla(
                hedef_dosya=hedef_dosya_yolu,
                basarili=True,
                detay=f"{self.algoritma_adi.upper()}-{self.mod_adi.upper()}"
            )

            return {
                "basarili": True,
                "kaynak_dosya": kaynak_dosya_yolu,
                "hedef_dosya": hedef_dosya_yolu,
                "toplam_boyut": dosya_boyutu
            }
        except Exception as hata_mesaji:
            return {"basarili": False, "hata": str(hata_mesaji)}
