import os
import sys
import itertools
from typing import List, Set, Iterable, Optional, Callable, Dict, Any, Tuple
from concurrent.futures import ProcessPoolExecutor, as_completed
import multiprocessing


LEET_TABLOSU = {
    'a': ['4', '@'],
    'e': ['3'],
    'i': ['1', '!'],
    'o': ['0'],
    's': ['5', '$'],
    't': ['7'],
    'b': ['8']
}


def leet_mutasyonlar(kelime: str, limit: int = 20) -> Set[str]:
    # leet speak permütasyonları üretir.
    sonuclar: Set[str] = {kelime, kelime.lower(), kelime.upper(), kelime.capitalize()}
    k_lower = kelime.lower()

    # tekil harf değişimleri.
    for i, ch in enumerate(k_lower):
        if ch in LEET_TABLOSU:
            for rep in LEET_TABLOSU[ch]:
                yeni = k_lower[:i] + rep + k_lower[i+1:]
                sonuclar.add(yeni)
                sonuclar.add(yeni.capitalize())

    # tüm harfleri değiştirme.
    tam_degisim = list(k_lower)
    for i, ch in enumerate(tam_degisim):
        if ch in LEET_TABLOSU:
            tam_degisim[i] = LEET_TABLOSU[ch][0]
    sonuclar.add("".join(tam_degisim))

    return set(list(sonuclar)[:limit])


def kural_tabanli_mutasyon(
    tohum_kelimeler: Iterable[str],
    max_toplam: int = 1000
) -> List[str]:
    # tohum kelimelere yaygın şifre kalıplarını uygular.
    havuz: Set[str] = set()
    sonekler = [
        "", "1", "12", "123", "1234", "12345", "123456",
        "!", "!!", "@", "#", "$", "2020", "2021", "2022",
        "2023", "2024", "2025", "2026", "_", ".", "01", "007"
    ]

    for ham in tohum_kelimeler:
        if not ham or len(ham) < 2:
            continue
        ham = ham.strip()
        varyasyonlar = leet_mutasyonlar(ham)
        for v in varyasyonlar:
            for s in sonekler:
                havuz.add(v + s)
                if len(havuz) >= max_toplam:
                    return list(havuz)
                if s:
                    havuz.add(s + v)
                if len(havuz) >= max_toplam:
                    return list(havuz)

    return list(havuz)


def sistem_sozluklerini_tara(max_kelime: int = 5000) -> List[str]:
    # sistemdeki sözlük dosyalarını akış halinde okur.
    aday_yollar = [
        "/usr/share/wordlists/rockyou.txt",
        "/usr/share/wordlists/fasttrack.txt",
        "/usr/share/dict/words",
        "/usr/share/dict/american-english",
        os.path.expanduser("~/Belgeler/txt/pass.txt"),
        os.path.expanduser("~/Desktop/passwords.txt")
    ]

    kelimeler: List[str] = []
    for yol in aday_yollar:
        if os.path.isfile(yol) and os.access(yol, os.R_OK):
            try:
                with open(yol, "r", encoding="utf-8", errors="ignore") as f:
                    for satir in f:
                        k = satir.strip()
                        if 3 <= len(k) <= 32:
                            kelimeler.append(k)
                            if len(kelimeler) >= max_kelime:
                                return kelimeler
            except Exception:
                continue
    return kelimeler


def _openssl_islemci_gorevi(argumanlar: Tuple[bytes, List[str], str]) -> Optional[Tuple[str, str, bytes]]:
    # alt süreç openssl kırma görevi.
    sifreli_veri, aday_kelimeler, algoritma = argumanlar
    from rescat.cozuculer.openssl_cozucu import OpenSslCozucu
    for k in aday_kelimeler:
        try:
            coz = OpenSslCozucu(
                parola_veya_anahtar=k.encode("utf-8", errors="ignore"),
                algoritma_adi=algoritma,
                kuru_calistirma=True
            )
            sonuc = coz.baytlari_coz(sifreli_veri)
            if sonuc and sonuc != sifreli_veri:
                return k, algoritma, sonuc
        except Exception:
            continue
    return None


class ParalelKiriciMotor:
    # tüm çekirdekleri kullanan kırma motoru.
    def __init__(self, islemci_sayisi: Optional[int] = None) -> None:
        self.islemci_sayisi = islemci_sayisi or max(1, multiprocessing.cpu_count())

    def openssl_paralel_kir(
        self,
        sifreli_baytlar: bytes,
        adaylar: List[str],
        algoritmalar: Tuple[str, ...] = ("aes-256-cbc", "aes-128-cbc"),
        parca_boyutu: int = 100
    ) -> Optional[Tuple[str, str, bytes]]:
        if not adaylar or not sifreli_baytlar:
            return None

        # kelimeleri parçalara böler.
        gorevler = []
        for algo in algoritmalar:
            for i in range(0, len(adaylar), parca_boyutu):
                parca = adaylar[i:i + parca_boyutu]
                gorevler.append((sifreli_baytlar, parca, algo))

        with ProcessPoolExecutor(max_workers=self.islemci_sayisi) as havuz:
            gelecekler = [havuz.submit(_openssl_islemci_gorevi, g) for g in gorevler]
            for f in as_completed(gelecekler):
                try:
                    res = f.result()
                    if res:
                        # başarılı süreç olunca diğerlerini durdurur.
                        for diger in gelecekler:
                            diger.cancel()
                        return res
                except Exception:
                    continue

        return None
