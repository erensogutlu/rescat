import os
from typing import Dict, List, Any, Optional, Tuple
from rescat.cekirdek.dosya_tanimlayici import BILINEN_SIHIRLI_BAYTLAR, sihirli_baytlardan_tur_tahmin_et


class KeystreamCozucu:
    """
    aes-ctr, chacha20, salsa20 ve xor gibi akış şifreleyicilerde (stream ciphers)
    aynı nonce / başlatma vektörünün (ıv) birden fazla dosyada tekrar kullanılması
    (nonce reuse) zafiyetini sömürerek anahtara ihtiyaç duymadan dosyaları çözen motor.
    """

    def __init__(self, kuru_calistirma: bool = False, yedek_al: bool = True) -> None:
        self.kuru_calistirma: bool = kuru_calistirma
        self.yedek_al: bool = yedek_al

    @staticmethod
    def xor_islemi(veri_a: bytes, veri_b: bytes) -> bytes:
        """ıki bayt dizisini xor'lar (en kisa uzunluk kadar)"""
        uzunluk = min(len(veri_a), len(veri_b))
        return bytes(veri_a[i] ^ veri_b[i] for i in range(uzunluk))

    def keystream_cikar(self, referans_duz_metin: bytes, sifreli_metin: bytes) -> bytes:
        """
        c = p ^ ks  =>  ks = c ^ p
        bilinen duz metin ile sifreli karsiligini xor'layarak ham anahtar akisini (keystream) cikarir.
        """
        return self.xor_islemi(sifreli_metin, referans_duz_metin)

    def keystream_dogrula(self, aday_keystream: bytes, baska_sifreli_dosyalar: List[str]) -> Tuple[bool, int, List[str]]:
        """
        cikarilan anahtar akisinin diger sifreli dosyalarda gecerli olup olmadigini
        sihirli bayt (magic bytes) kontrolu ile dogrular.
        """
        if len(aday_keystream) < 16:
            return False, 0, []

        basarili_sayisi = 0
        dogrulanan_turler: List[str] = []

        for dosya_yolu in baska_sifreli_dosyalar[:20]:
            try:
                with open(dosya_yolu, "rb") as f:
                    baslik_sifreli = f.read(min(64, len(aday_keystream)))

                if len(baslik_sifreli) >= 16:
                    cozulmus_baslik = self.xor_islemi(baslik_sifreli, aday_keystream[:len(baslik_sifreli)])
                    tur = sihirli_baytlardan_tur_tahmin_et(cozulmus_baslik)
                    if tur:
                        basarili_sayisi += 1
                        if tur not in dogrulanan_turler:
                            dogrulanan_turler.append(tur)
            except Exception:
                continue

        return basarili_sayisi > 0, basarili_sayisi, dogrulanan_turler

    def tekil_dosya_coz(self, sifreli_dosya: str, keystream: bytes, hedef_cikti: Optional[str] = None) -> Dict[str, Any]:
        """
        cikarilan keystream ile tekil bir sifreli dosyayi cozer.
        """
        if not os.path.exists(sifreli_dosya):
            return {"basarili": False, "hata": "Dosya bulunamadi"}

        try:
            with open(sifreli_dosya, "rb") as f:
                sifreli_veri = f.read()

            boyut = len(sifreli_veri)
            if boyut == 0:
                return {"basarili": False, "hata": "Dosya bos"}

            # anahtar akışı boyutunca şifre çözer.
            cozulecek_boyut = min(boyut, len(keystream))
            cozulmus_kisim = self.xor_islemi(sifreli_veri[:cozulecek_boyut], keystream[:cozulecek_boyut])
            kalan_kisim = sifreli_veri[cozulecek_boyut:]

            tam_veri = cozulmus_kisim + kalan_kisim
            dogrulanan_tur = sihirli_baytlardan_tur_tahmin_et(tam_veri[:32])

            cikti_yolu = hedef_cikti or (sifreli_dosya + ".cozuldu")
            if not self.kuru_calistirma:
                if self.yedek_al and not os.path.exists(sifreli_dosya + ".bak"):
                    import shutil
                    shutil.copy2(sifreli_dosya, sifreli_dosya + ".bak")

                with open(cikti_yolu, "wb") as f_out:
                    f_out.write(tam_veri)

            return {
                "basarili": True,
                "dosya": sifreli_dosya,
                "cikti": cikti_yolu,
                "cozulen_bayt": cozulecek_boyut,
                "toplam_bayt": boyut,
                "tamami_cozuldu_mu": cozulecek_boyut == boyut,
                "dogrulanan_tur": dogrulanan_tur,
                "kuru_calistirma": self.kuru_calistirma
            }

        except Exception as e:
            return {"basarili": False, "hata": str(e)}

    def coklu_keystream_cozumu(
        self,
        referans_orijinal_dosya: str,
        referans_sifreli_dosya: str,
        hedef_dizin_veya_dosyalar: List[str]
    ) -> Dict[str, Any]:
        """
        bir adet bilinen orijinal saglam dosya ve onun sifrelenmis kopyasindan
        keystream'i cikarir ve hedef listedeki tum kardes dosyalari otomatik cozer.
        """
        if not os.path.exists(referans_orijinal_dosya) or not os.path.exists(referans_sifreli_dosya):
            return {"basarili": False, "hata": "Referans dosyalardan biri veya ikisi bulunamadi"}

        try:
            with open(referans_orijinal_dosya, "rb") as f_orj:
                orj_veri = f_orj.read()
            with open(referans_sifreli_dosya, "rb") as f_sif:
                sif_veri = f_sif.read()

            keystream = self.keystream_cikar(orj_veri, sif_veri)
            if len(keystream) < 16:
                return {"basarili": False, "hata": "Keystream uzunlugu cok kisa"}

            # diğer dosyalar üzerinde doğrular.
            gecerli_mi, eslesen_sayi, turler = self.keystream_dogrula(keystream, hedef_dizin_veya_dosyalar)

            cozulen_dosyalar: List[Dict[str, Any]] = []
            for dosya in hedef_dizin_veya_dosyalar:
                if dosya in (referans_orijinal_dosya, referans_sifreli_dosya):
                    continue
                sonuc = self.tekil_dosya_coz(dosya, keystream)
                if sonuc.get("basarili"):
                    cozulen_dosyalar.append(sonuc)

            return {
                "basarili": len(cozulen_dosyalar) > 0 or gecerli_mi,
                "keystream_uzunlugu": len(keystream),
                "eslesen_turler": turler,
                "cozulen_toplam_dosya": len(cozulen_dosyalar),
                "detaylar": cozulen_dosyalar
            }

        except Exception as e:
            return {"basarili": False, "hata": str(e)}
