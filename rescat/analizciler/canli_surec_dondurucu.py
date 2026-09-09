import os
import sys
import signal
import platform
from typing import Dict, List, Optional, Any
from rescat.analizciler.bellek_anahtar_avcisi import bellek_dosyasini_tara


class CanliSurecDondurucu:
    """
    sistemde calismakta olan fidye yazilimlarini aninda dondurarak (sıgstop / suspend)
    sifrelemeyi durduran ve calisma belleginden (ram) kripto anahtarlarini
    canli olarak yakalayan olay mudahale (ır) modulu.
    """
    BILINEN_TEHDIT_DESENLERI = [
        "encrypt", "locker", "ransom", "lockbit", "akira", "blackcat",
        "conti", "babuk", "wanacrypt", "crypt", "vault"
    ]

    @classmethod
    def supheli_surecleri_tara(cls) -> List[Dict[str, Any]]:
        """
        calisan surecler arasinda supheli fidye yazilimi olabilecek islemleri listeler.
        """
        supheliler = []
        is_linux = platform.system().lower() == "linux"

        if is_linux and os.path.exists("/proc"):
            for pid_dir in os.listdir("/proc"):
                if not pid_dir.isdigit():
                    continue
                pid = int(pid_dir)
                try:
                    cmdline_yolu = f"/proc/{pid}/cmdline"
                    with open(cmdline_yolu, "rb") as f:
                        komut = f.read().replace(b"\x00", b" ").decode("utf-8", errors="ignore").strip()

                    comm_yolu = f"/proc/{pid}/comm"
                    with open(comm_yolu, "r", errors="ignore") as f:
                        ad = f.read().strip()

                    kucuk_komut = komut.lower()
                    kucuk_ad = ad.lower()

                    if any(desen in kucuk_komut or desen in kucuk_ad for desen in cls.BILINEN_TEHDIT_DESENLERI):
                        # kendi sürecimizi hariç tutar.
                        if pid != os.getpid():
                            supheliler.append({
                                "pid": pid,
                                "ad": ad,
                                "komut": komut
                            })
                except Exception:
                    continue

        return supheliler

    @classmethod
    def sureci_dondur(cls, pid: int) -> bool:
        """
        hedef surecin calismasini derhal dondurur.
        linux: sıgstop gonderir.
        windows: ntsuspendprocess cagirir.
        """
        try:
            if platform.system().lower() == "linux":
                os.kill(pid, signal.SIGSTOP)
                return True
            elif platform.system().lower() == "windows":
                import ctypes
                PROCESS_ALL_ACCESS = 0x1F0FFF
                handle = ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
                if handle:
                    ntdll = ctypes.windll.ntdll
                    ntdll.NtSuspendProcess(handle)
                    ctypes.windll.kernel32.CloseHandle(handle)
                    return True
        except Exception:
            return False
        return False

    @classmethod
    def sureci_devam_ettir(cls, pid: int) -> bool:
        """dondurulan sureci devam ettirir (sıgcont)"""
        try:
            if platform.system().lower() == "linux":
                os.kill(pid, signal.SIGCONT)
                return True
            elif platform.system().lower() == "windows":
                import ctypes
                PROCESS_ALL_ACCESS = 0x1F0FFF
                handle = ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
                if handle:
                    ntdll = ctypes.windll.ntdll
                    ntdll.NtResumeProcess(handle)
                    ctypes.windll.kernel32.CloseHandle(handle)
                    return True
        except Exception:
            return False
        return False

    @classmethod
    def surec_bellegini_dok(cls, pid: int, cikti_yolu: str, maks_mb: int = 256) -> bool:
        """
        hedef surecin bellek sayfalarini (/proc/pid/mem) okuyarak diske döküm alır.
        """
        try:
            maps_yolu = f"/proc/{pid}/maps"
            mem_yolu = f"/proc/{pid}/mem"

            if not (os.path.exists(maps_yolu) and os.path.exists(mem_yolu)):
                return False

            toplam_yazilan = 0
            maks_bayt = maks_mb * 1024 * 1024

            with open(maps_yolu, "r") as f_maps, open(mem_yolu, "rb") as f_mem, open(cikti_yolu, "wb") as f_out:
                for satir in f_maps:
                    parcalar = satir.strip().split()
                    if len(parcalar) < 2:
                        continue
                    izinler = parcalar[1]
                    # salt okunabilir ve yazılabilir bellek sayfalarını alır.
                    if "r" in izinler and ("w" in izinler or "[heap]" in satir or "[stack]" in satir):
                        adresler = parcalar[0].split("-")
                        baslangic = int(adresler[0], 16)
                        bitis = int(adresler[1], 16)
                        uzunluk = bitis - baslangic

                        if toplam_yazilan + uzunluk > maks_bayt:
                            uzunluk = maks_bayt - toplam_yazilan

                        try:
                            f_mem.seek(baslangic)
                            veri = f_mem.read(uzunluk)
                            f_out.write(veri)
                            toplam_yazilan += len(veri)
                        except Exception:
                            continue

                        if toplam_yazilan >= maks_bayt:
                            break

            return toplam_yazilan > 0
        except Exception:
            return False

    @classmethod
    def dondur_ve_anahtar_yakala(cls, pid: int, gecici_dokum_yolu: str) -> Dict[str, Any]:
        """
        tek adimda sureci dondurur, bellegini ceker ve kripto anahtarlarini tarar.
        """
        donduruldu = cls.sureci_dondur(pid)
        dokum_basarili = cls.surec_bellegini_dok(pid, gecici_dokum_yolu)
        
        anahtarlar = {}
        if dokum_basarili:
            anahtarlar = bellek_dosyasini_tara(gecici_dokum_yolu)

        return {
            "pid": pid,
            "donduruldu": donduruldu,
            "dokum_alindi": dokum_basarili,
            "anahtarlar": anahtarlar
        }
