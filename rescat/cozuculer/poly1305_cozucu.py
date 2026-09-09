import os
from typing import Optional, Dict, Any
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from rescat.cozuculer.temel_cozucu import TemelCozucu


class Poly1305Cozucu(TemelCozucu):
    """
    chacha20-poly1305 (ıetf aead) algoritması ile şifrelenmiş fidye yazılımı
    dosyalarını (blackcat/alphv, lockbit 3.0, babuk vb.) çözen gelişmiş motor.
    """

    def __init__(
        self,
        anahtar_baytlari: bytes,
        nonce: Optional[bytes] = None,
        nonce_dosya_basinda_mi: bool = True,
        ek_veri_aad: Optional[bytes] = None,
        kuru_calistirma: bool = False,
        yedek_al: bool = True,
        hedef_cikti_dizini: Optional[str] = None
    ) -> None:
        super().__init__(
            kuru_calistirma=kuru_calistirma,
            yedek_al=yedek_al,
            hedef_cikti_dizini=hedef_cikti_dizini
        )
        self.anahtar_baytlari: bytes = anahtar_baytlari
        self.nonce: Optional[bytes] = nonce
        self.nonce_dosya_basinda_mi: bool = nonce_dosya_basinda_mi
        self.ek_veri_aad: Optional[bytes] = ek_veri_aad

        if len(self.anahtar_baytlari) != 32:
            raise ValueError("ChaCha20-Poly1305 anahtarı tam olarak 32 bayt (256-bit) olmalıdır.")

    def baytlari_coz(self, sifreli_baytlar: bytes) -> bytes:
        """
        chacha20-poly1305 aead desifreleme uygular.
        dosya başı 12-bayt nonce ve dosya sonu 16-bayt mac tag kombinasyonlarını otomatik dener.
        """
        toplam_uzunluk = len(sifreli_baytlar)
        if toplam_uzunluk < 16:
            raise ValueError("Veri boyutu Poly1305 tag ve şifreli metin için yetersiz (en az 16 bayt).")

        aead = ChaCha20Poly1305(self.anahtar_baytlari)
        aad = self.ek_veri_aad

        # 1. senaryo: nonce parametre olarak verilmişse.
        if self.nonce is not None:
            kullanilacak_nonce = self.nonce[:12] if len(self.nonce) >= 12 else self.nonce.ljust(12, b"\x00")
            try:
                return aead.decrypt(kullanilacak_nonce, sifreli_baytlar, aad)
            except Exception:
                pass

        # 2. senaryo: standart ietf zarf yapısı.
        if self.nonce_dosya_basinda_mi and toplam_uzunluk >= 28:
            olasi_nonce = sifreli_baytlar[:12]
            olasi_sifreli_ve_tag = sifreli_baytlar[12:]
            try:
                return aead.decrypt(olasi_nonce, olasi_sifreli_ve_tag, aad)
            except Exception:
                pass

        # 3. senaryo: sıfır baytlı nonce yapısı.
        sifir_nonce = b"\x00" * 12
        try:
            return aead.decrypt(sifir_nonce, sifreli_baytlar, aad)
        except Exception:
            pass

        # 4. senaryo: ters zarf yapısı.
        if toplam_uzunluk >= 28:
            kuyruk_nonce = sifreli_baytlar[-28:-16]
            kuyruk_sifreli_ve_tag = sifreli_baytlar[:-28] + sifreli_baytlar[-16:]
            try:
                return aead.decrypt(kuyruk_nonce, kuyruk_sifreli_ve_tag, aad)
            except Exception:
                pass

        raise ValueError("ChaCha20-Poly1305 AEAD desifreleme başarısız oldu (geçersiz anahtar, Nonce veya Tag bozulması).")
