from typing import Optional, Dict, Any, List, Tuple
from rescat.cozuculer.temel_cozucu import TemelCozucu
from rescat.cozuculer.aes_cozucu import AesCozucu
from rescat.cozuculer.chacha_cozucu import ChaChaCozucu
from rescat.cozuculer.salsa20_cozucu import Salsa20Cozucu
from rescat.cozuculer.rc4_cozucu import Rc4Cozucu
from rescat.cozuculer.tea_cozucu import TeaCozucu, XteaCozucu, XxteaCozucu
from rescat.cozuculer.twofish_cozucu import TwofishCozucu
from rescat.cozuculer.blok_cozucu import BlokCozucu, DESTEKLENEN_BLOK_ALGORITMALARI
from rescat.cozuculer.openssl_cozucu import OpenSslCozucu
from rescat.cozuculer.xor_cozucu import XorCozucu
from rescat.cozuculer.djvu_cozucu import DjvuCozucu
from rescat.cozuculer.poly1305_cozucu import Poly1305Cozucu
from rescat.cozuculer.x25519_cozucu import X25519HibritCozucu
from rescat.cozuculer.akici_sosemanuk import SosemanukCozucu
from rescat.cekirdek.dosya_tanimlayici import sihirli_baytlardan_tur_tahmin_et, format_icerik_dogrula


class CozucuFabrikasi:
    # tüm kripto ve zararlı çözücüleri yöneten evrensel fabrika.

    @classmethod
    def desteklenen_algoritmalar(cls) -> List[str]:
        return [
            "aes", "chacha20", "poly1305", "chachapoly1305", "salsa20", "rc4", "tea", "xtea", "xxtea",
            "twofish", "blowfish", "3des", "cast5", "camellia", "idea",
            "seed", "sm4", "openssl", "xor", "djvu", "x25519", "curve25519", "sosemanuk"
        ]

    @classmethod
    def desteklenen_algoritmalari_listele(cls) -> List[str]:
        return cls.desteklenen_algoritmalar()

    @classmethod
    def cozucu_uret(
        cls,
        algoritma: Optional[str] = None,
        anahtar_baytlari: bytes = b"",
        mod: str = "cbc",
        iv: Optional[bytes] = None,
        kuru_calistirma: bool = False,
        yedek_al: bool = True,
        hedef_cikti_dizini: Optional[str] = None,
        algoritma_adi: Optional[str] = None,
        mod_adi: Optional[str] = None,
        baslatma_vektoru: Optional[bytes] = None,
        **ekstra_parametreler
    ) -> TemelCozucu:
        secilen_algo = algoritma or algoritma_adi or "aes"
        mod = mod_adi or mod
        iv = baslatma_vektoru if baslatma_vektoru is not None else iv
        algo = secilen_algo.lower().replace("-", "").replace("_", "").strip()

        # 1. aes çözümü.
        if "aes" in algo:
            return AesCozucu(
                anahtar_baytlari=anahtar_baytlari,
                mod_adi=mod,
                baslatma_vektoru=iv,
                kuru_calistirma=kuru_calistirma,
                yedek_al=yedek_al,
                hedef_cikti_dizini=hedef_cikti_dizini
            )

        # 2. chacha20-poly1305 çözümü.
        if "poly1305" in algo or "chachapoly" in algo:
            return Poly1305Cozucu(
                anahtar_baytlari=anahtar_baytlari,
                nonce=iv,
                nonce_dosya_basinda_mi=(iv is None),
                kuru_calistirma=kuru_calistirma,
                yedek_al=yedek_al,
                hedef_cikti_dizini=hedef_cikti_dizini
            )

        # 3. chacha20 çözümü.
        if "chacha" in algo:
            return ChaChaCozucu(
                anahtar_baytlari=anahtar_baytlari,
                guvenlik_no=iv,
                nonce_dosya_basinda_mi=(iv is None),
                kuru_calistirma=kuru_calistirma,
                yedek_al=yedek_al,
                hedef_cikti_dizini=hedef_cikti_dizini
            )

        # 4. salsa20 çözümü.
        if "salsa" in algo:
            dongu = ekstra_parametreler.get("dongu_sayisi", 20)
            return Salsa20Cozucu(
                anahtar_baytlari=anahtar_baytlari,
                nonce=iv,
                nonce_dosya_basinda_mi=(iv is None),
                dongu_sayisi=dongu,
                kuru_calistirma=kuru_calistirma,
                yedek_al=yedek_al,
                hedef_cikti_dizini=hedef_cikti_dizini
            )

        # 5. rc4 çözümü.
        if algo in ("rc4", "arc4"):
            return Rc4Cozucu(
                anahtar_baytlari=anahtar_baytlari,
                kuru_calistirma=kuru_calistirma,
                yedek_al=yedek_al,
                hedef_cikti_dizini=hedef_cikti_dizini
            )

        # 6. tea ailesi çözümü.
        if algo == "tea":
            return TeaCozucu(
                anahtar_baytlari=anahtar_baytlari,
                mod_adi=mod,
                baslatma_vektoru=iv,
                kuru_calistirma=kuru_calistirma,
                yedek_al=yedek_al,
                hedef_cikti_dizini=hedef_cikti_dizini
            )
        if algo == "xtea":
            return XteaCozucu(
                anahtar_baytlari=anahtar_baytlari,
                mod_adi=mod,
                baslatma_vektoru=iv,
                kuru_calistirma=kuru_calistirma,
                yedek_al=yedek_al,
                hedef_cikti_dizini=hedef_cikti_dizini
            )
        if algo == "xxtea":
            return XxteaCozucu(
                anahtar_baytlari=anahtar_baytlari,
                kuru_calistirma=kuru_calistirma,
                yedek_al=yedek_al,
                hedef_cikti_dizini=hedef_cikti_dizini
            )

        # 7. twofish çözümü.
        if "twofish" in algo:
            return TwofishCozucu(
                anahtar_baytlari=anahtar_baytlari,
                mod_adi=mod,
                baslatma_vektoru=iv,
                kuru_calistirma=kuru_calistirma,
                yedek_al=yedek_al,
                hedef_cikti_dizini=hedef_cikti_dizini
            )

        # 8. diğer blok algoritmaları çözümü.
        for blok_algo in DESTEKLENEN_BLOK_ALGORITMALARI:
            if blok_algo in algo:
                return BlokCozucu(
                    algoritma_adi=blok_algo,
                    anahtar_baytlari=anahtar_baytlari,
                    mod_adi=mod,
                    baslatma_vektoru=iv,
                    kuru_calistirma=kuru_calistirma,
                    yedek_al=yedek_al,
                    hedef_cikti_dizini=hedef_cikti_dizini
                )

        # 9. openssl salted çözümü.
        if "openssl" in algo or "salted" in algo:
            return OpenSslCozucu(
                parola_veya_anahtar=anahtar_baytlari,
                algoritma_adi=ekstra_parametreler.get("openssl_algo", "aes-256-cbc"),
                kuru_calistirma=kuru_calistirma,
                yedek_al=yedek_al,
                hedef_cikti_dizini=hedef_cikti_dizini
            )

        # 10. xor çözümü.
        if "xor" in algo:
            kaydirmali = ekstra_parametreler.get("kaydirmali", False)
            return XorCozucu(
                anahtar_baytlari=anahtar_baytlari,
                kaydirmali_mi=kaydirmali,
                kuru_calistirma=kuru_calistirma,
                yedek_al=yedek_al,
                hedef_cikti_dizini=hedef_cikti_dizini
            )

        # 11. stop/djvu çözümü.
        if "djvu" in algo or "stop" in algo:
            return DjvuCozucu(
                anahtar_baytlari=anahtar_baytlari,
                kuru_calistirma=kuru_calistirma,
                yedek_al=yedek_al,
                hedef_cikti_dizini=hedef_cikti_dizini
            )

        # 12. x25519 hibrit çözümü.
        if algo in ("x25519", "curve25519", "ecdh"):
            simetrik = ekstra_parametreler.get("simetrik_algoritma", "chacha20")
            konum = ekstra_parametreler.get("anahtar_konumu", "basinda")
            kdf = ekstra_parametreler.get("kdf_tipi", "sha256")
            return X25519HibritCozucu(
                ozel_anahtar_baytlari=anahtar_baytlari,
                simetrik_algoritma=simetrik,
                anahtar_konumu=konum,
                kdf_tipi=kdf,
                kuru_calistirma=kuru_calistirma,
                yedek_al=yedek_al,
                hedef_cikti_dizini=hedef_cikti_dizini
            )

        # 13. sosemanuk çözümü.
        if "sosemanuk" in algo:
            return SosemanukCozucu(
                anahtar_baytlari=anahtar_baytlari,
                baslatma_vektoru=iv,
                iv_dosya_basinda_mi=(iv is None),
                kuru_calistirma=kuru_calistirma,
                yedek_al=yedek_al,
                hedef_cikti_dizini=hedef_cikti_dizini
            )

        # varsayılan olarak aes ile dener.
        return AesCozucu(
            anahtar_baytlari=anahtar_baytlari,
            mod_adi=mod,
            baslatma_vektoru=iv,
            kuru_calistirma=kuru_calistirma,
            yedek_al=yedek_al,
            hedef_cikti_dizini=hedef_cikti_dizini
        )

    @classmethod
    def aday_anahtarla_otomatik_dene(
        cls,
        sifreli_baytlar: bytes,
        anahtar: bytes,
        aday_algoritmalar: Optional[List[str]] = None
    ) -> Optional[Dict[str, Any]]:
        # anahtar adayıyla desteklenen algoritmalarda deneme yapar.
        # sonuç geçerli format verirse sözlük olarak döndürür.
        if not aday_algoritmalar:
            aday_algoritmalar = [
                "aes", "poly1305", "chacha20", "salsa20", "rc4", "twofish",
                "blowfish", "tea", "xtea", "camellia", "3des"
            ]

        for algo_adi in aday_algoritmalar:
            try:
                cozucu = cls.cozucu_uret(algo_adi, anahtar, kuru_calistirma=True)
                cozulmus = cozucu.baytlari_coz(sifreli_baytlar[:2048])
                gecerli, tur = format_icerik_dogrula(cozulmus)
                if gecerli and tur:
                    return {
                        "basarili": True,
                        "algoritma": algo_adi,
                        "cozucu": cozucu,
                        "cozulmus_veri": cozulmus,
                        "dogrulanan_tur": tur
                    }
            except Exception:
                continue

        return None
