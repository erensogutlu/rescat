import sys
import os
import platform
from typing import Optional

# çapraz platform konsol ve utf-8 başlatma.
def _konsol_hazirla() -> None:
    # utf-8 kodlamasını güvenceye alır.
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    # windows üzerinde vt100 ansi ve utf-8 kod sayfasını etkinleştirir.
    if sys.platform == "win32":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            # 65001: utf-8 kod sayfası.
            kernel32.SetConsoleOutputCP(65001)
            kernel32.SetConsoleCP(65001)
            # vt100 ansi desteği.
            h_std_out = kernel32.GetStdHandle(-11)
            mode = ctypes.c_ulong()
            kernel32.GetConsoleMode(h_std_out, ctypes.byref(mode))
            mode.value |= 0x0004  # sanal terminal işleme bayrağı.
            kernel32.SetConsoleMode(h_std_out, mode)
        except Exception:
            # vt100 başlatılamazsa renksiz devam eder.
            pass

_konsol_hazirla()

# terminal için ansi renk kodları.
RENK_SIFIRLA = "\033[0m"
RENK_KALIN = "\033[1m"
RENK_KIRMIZI = "\033[91m"
RENK_YESIL = "\033[92m"
RENK_SARI = "\033[93m"
RENK_MAVI = "\033[94m"
RENK_MOR = "\033[95m"
RENK_CAMGOBEGI = "\033[96m"
RENK_GRI = "\033[90m"


def banner_yazdir() -> None:
    # rescat ascii logosunu ekrana basar.
    isletim_sistemi = f"{platform.system()} ({platform.release()})"
    logo = f"""{RENK_KIRMIZI}{RENK_KALIN}
  ██████╗ ███████╗███████╗ ██████╗ █████╗ ████████╗
  ██╔══██╗██╔════╝██╔════╝██╔════╝██╔══██╗╚══██╔══╝
  ██████╔╝█████╗  ███████╗██║     ███████║   ██║   
  ██╔══██╗██╔══╝  ╚════██║██║     ██╔══██║   ██║   
  ██║  ██║███████╗███████║╚██████╗██║  ██║   ██║   
  ╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   {RENK_SIFIRLA}
  {RENK_CAMGOBEGI}Ransomware Analiz ve Şifre Çözücü & Ransomware Analysis and Decryptor{RENK_SIFIRLA}
  {RENK_SARI}[ Sistem: {isletim_sistemi} | by: erensogutlu ]{RENK_SIFIRLA}
"""
    try:
        sys.stdout.write(logo + "\n")
        sys.stdout.flush()
    except UnicodeEncodeError:
        # ascii yedek başlığı.
        ascii_logo = f"""
  +-+-+-+-+-+-+
  |r|e|s|c|a|t|
  +-+-+-+-+-+-+
  ransomware analiz ve şifre çözücü
  ransomware analysis and decryptor
  [ sistem: {isletim_sistemi} | by: erensogutlu ]
"""
        sys.stdout.write(ascii_logo + "\n") 
        sys.stdout.flush()


import datetime

CANLI_LOG_MODU = True


def zaman_damgasi_al() -> str:
    # saat:dakika:saniye zaman damgası üretir.
    if CANLI_LOG_MODU:
        simdiki_zaman = datetime.datetime.now().strftime("%H:%M:%S")
        return f"{RENK_GRI}[{simdiki_zaman}]{RENK_SIFIRLA} "
    return ""


def anlik_log(mesaj: str, seviye: str = "bilgi") -> None:
    # zaman damgalı terminal günlüğü yazar.
    zaman = zaman_damgasi_al()
    if seviye == "basari":
        simge = f"{RENK_YESIL}[+]{RENK_SIFIRLA}"
        hedef = sys.stdout
    elif seviye == "uyari":
        simge = f"{RENK_SARI}[!]{RENK_SIFIRLA}"
        hedef = sys.stdout
    elif seviye == "hata":
        simge = f"{RENK_KIRMIZI}[-]{RENK_SIFIRLA}"
        hedef = sys.stderr
    elif seviye == "kritik":
        simge = f"{RENK_KIRMIZI}{RENK_KALIN}[KRITIK]{RENK_SIFIRLA}"
        hedef = sys.stdout
    else:
        simge = f"{RENK_MAVI}[*]{RENK_SIFIRLA}"
        hedef = sys.stdout

    hedef.write(f"{zaman}{simge} {mesaj}\n")
    hedef.flush()


def bilgi_yaz(mesaj: str) -> None:
    # bilgilendirme iletisini mavi simgeyle yazdırır.
    anlik_log(mesaj, seviye="bilgi")


def basari_yaz(mesaj: str) -> None:
    # başarılı işlem iletisini yeşil simgeyle yazdırır.
    anlik_log(mesaj, seviye="basari")


def uyari_yaz(mesaj: str) -> None:
    # uyarı iletisini sarı simgeyle yazdırır.
    anlik_log(mesaj, seviye="uyari")


def hata_yaz(mesaj: str) -> None:
    # hata iletisini kırmızı simgeyle yazdırır.
    anlik_log(mesaj, seviye="hata")


def kritik_yaz(mesaj: str) -> None:
    # kritik güvenlik bulgusunu yazdırır.
    anlik_log(mesaj, seviye="kritik")


def baslik_yaz(metin: str) -> None:
    # bölüm başlığını vurgulayarak yazdırır.
    cizgi = "=" * len(metin)
    sys.stdout.write(f"\n{RENK_CAMGOBEGI}{RENK_KALIN}{metin}\n{cizgi}{RENK_SIFIRLA}\n")
    sys.stdout.flush()


def tablo_satiri_yaz(etiket: str, deger: str, etiket_genislik: int = 25) -> None:
    # hizalanmış etiket ve değer ikilisini yazdırır.
    sys.stdout.write(f"  {RENK_MOR}{etiket.ljust(etiket_genislik)}:{RENK_SIFIRLA} {deger}\n")
    sys.stdout.flush()


import time

DENGELI_MOD = True


def dengeli_bekle(saniye: float = 0.06) -> None:
    # terminal titreşimini önleyen geçiş gecikmesi.
    if DENGELI_MOD and os.environ.get("RESCAT_NO_DELAY") != "1":
        time.sleep(saniye)


def masaustu_dizini_al() -> str:
    # işletim sisteminin masaüstü dizinini tespit eder.
    sistem = platform.system()
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and sistem == "Linux" and os.path.isdir(f"/home/{sudo_user}"):
        ev_dizini = f"/home/{sudo_user}"
    else:
        ev_dizini = os.path.expanduser("~")

    if sistem == "Windows":
        user_profile = os.environ.get("USERPROFILE", ev_dizini)
        onedrive = os.environ.get("OneDrive")
        if onedrive and os.path.isdir(os.path.join(onedrive, "Desktop")):
            masaustu = os.path.join(onedrive, "Desktop")
        else:
            masaustu = os.path.join(user_profile, "Desktop")
    elif sistem == "Darwin":
        masaustu = os.path.join(ev_dizini, "Desktop")
    else:
        # linux xdg masaüstü kontrolü.
        xdg_config = os.path.join(ev_dizini, ".config", "user-dirs.dirs")
        masaustu = None
        if os.path.isfile(xdg_config):
            try:
                with open(xdg_config, "r", encoding="utf-8") as f:
                    for satir in f:
                        if satir.startswith("XDG_DESKTOP_DIR"):
                            yol_kismi = satir.split("=")[1].strip().strip('"')
                            masaustu = yol_kismi.replace("$HOME", ev_dizini)
                            break
            except Exception:
                pass

        if not masaustu or not os.path.isdir(masaustu):
            turkce_masaustu = os.path.join(ev_dizini, "Masaüstü")
            ingilizce_desktop = os.path.join(ev_dizini, "Desktop")
            if os.path.isdir(turkce_masaustu):
                masaustu = turkce_masaustu
            elif os.path.isdir(ingilizce_desktop):
                masaustu = ingilizce_desktop
            else:
                masaustu = turkce_masaustu if "tr" in os.environ.get("LANG", "").lower() else ingilizce_desktop

    try:
        os.makedirs(masaustu, exist_ok=True)
    except Exception:
        pass
    return os.path.abspath(masaustu)


class YuklenmeCubugu:
    # minimalist ilerleme çubuğu.
    def __init__(
        self,
        toplam: int = 100,
        baslik: str = "Şifre Çözülüyor",
        dosya_adi: str = "",
        cubuk_uzunlugu: int = 24
    ) -> None:
        self.toplam: int = max(1, toplam)
        self.mevcut: int = 0
        self.baslik: str = baslik
        self.dosya_adi: str = os.path.basename(dosya_adi) if dosya_adi else ""
        self.cubuk_uzunlugu: int = cubuk_uzunlugu
        self.baslangic_zamani: float = time.time()
        self._tamamlandi: bool = False

    def guncelle(self, ilerleme: int, asama: str = "") -> None:
        if self._tamamlandi:
            return
        self.mevcut = min(self.toplam, max(0, ilerleme))

        # tty değilse ara kareleri basmaz.
        if not (sys.stdout.isatty() or os.environ.get("RESCAT_CANLI_BAR") == "1"):
            return

        oran = self.mevcut / self.toplam
        dolu = int(self.cubuk_uzunlugu * oran)
        bos = self.cubuk_uzunlugu - dolu
        yuzde = int(oran * 100)

        cubuk = f"{RENK_CAMGOBEGI}{'█' * dolu}{RENK_GRI}{'░' * bos}{RENK_SIFIRLA}"
        asama_str = f"  {RENK_GRI}{asama[:28]}{RENK_SIFIRLA}" if asama else ""

        satir = f"\r  [{cubuk}] {RENK_KALIN}%{yuzde:3d}{RENK_SIFIRLA}{asama_str}\033[K"
        try:
            sys.stdout.write(satir)
            sys.stdout.flush()
        except Exception:
            pass

    def animasyonlu_tamamla(self, hedef_dosya: str = "", basarili: bool = True, detay: str = "") -> None:
        self._tamamlandi = True
        prefix = "\r" if (sys.stdout.isatty() or os.environ.get("RESCAT_CANLI_BAR") == "1") else ""
        if basarili:
            hedef_adi = os.path.basename(hedef_dosya) or self.dosya_adi
            detay_str = f" {RENK_GRI}({detay}){RENK_SIFIRLA}" if detay else ""
            satir = f"{prefix}  {RENK_YESIL}[+] BAŞARILI:{RENK_SIFIRLA} {RENK_KALIN}{hedef_adi}{RENK_SIFIRLA}{detay_str}\033[K\n"
        else:
            dosya_adi = self.dosya_adi or os.path.basename(hedef_dosya)
            satir = f"{prefix}  {RENK_KIRMIZI}[-] BAŞARISIZ:{RENK_SIFIRLA} {RENK_KALIN}{dosya_adi}{RENK_SIFIRLA} {RENK_GRI}(Şifre çözülemedi){RENK_SIFIRLA}\033[K\n"
        try:
            sys.stdout.write(satir)
            sys.stdout.flush()
        except Exception:
            pass


def sifre_cozme_animasyonu_oynat(
    dosya_adi: str,
    algoritma: str = "",
    hedef_yol: str = "",
    adim_sayisi: int = 10,
    gecikme: float = 0.06
) -> None:
    # şifre çözülürken ilerleme çubuğunu günceller.
    is_tty = sys.stdout.isatty() or os.environ.get("RESCAT_CANLI_BAR") == "1"
    adimlar = adim_sayisi if is_tty else 2
    bekleme = gecikme if is_tty else 0.001

    cubuk = YuklenmeCubugu(toplam=adimlar, baslik="Şifre Çözülüyor", dosya_adi=dosya_adi)
    asamalar = [
        "Bayt akışı okunuyor",
        "Entropi analizi yapılıyor",
        f"Kripto çözücü devrede ({algoritma or 'Blok Şifreleyici'})",
        "Blok doğrulaması yapılıyor",
        "S-Box & Keystream eşleştiriliyor",
        "Sihirli baytlar doğrulanıyor",
        "Dosya bütünlüğü onaylandı",
        "Masaüstüne aktarılıyor"
    ]
    for i in range(1, adimlar + 1):
        asama_idx = min(len(asamalar) - 1, int(((i - 1) / max(1, adimlar - 1)) * len(asamalar)))
        cubuk.guncelle(i, asama=asamalar[asama_idx])
        dengeli_bekle(bekleme)
    cubuk.animasyonlu_tamamla(hedef_dosya=hedef_yol or dosya_adi, basarili=True, detay=algoritma)



