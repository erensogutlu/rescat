import os
import sys
import threading
from rescat.yardimcilar.konsol import (
    banner_yazdir,
    bilgi_yaz,
    basari_yaz,
    uyari_yaz,
    hata_yaz,
    baslik_yaz,
    tablo_satiri_yaz
)
from rescat.otonom import OtonomKurtarmaMotoru


def akilli_yol_coz(girdi: str) -> str:
    # girilen dosya yolunu akıllı şekilde çözümler.
    if not girdi:
        return ""
    temiz = girdi.strip().strip("\"'")

    # 1. doğrudan var mı kontrolü.
    if os.path.exists(temiz):
        return os.path.abspath(temiz)

    # 2. tilde genişleterek kontrol.
    genisletilmis = os.path.expanduser(temiz)
    if os.path.exists(genisletilmis):
        return os.path.abspath(genisletilmis)

    # 3. sudo altında kullanıcı ev dizini kontrolü.
    sudo_user = os.environ.get("SUDO_USER")
    ev_dizinleri = [os.path.expanduser("~")]
    if sudo_user:
        ev_dizinleri.append(f"/home/{sudo_user}")

    for ev in ev_dizinleri:
        olasi = os.path.join(ev, temiz.lstrip("/"))
        if os.path.exists(olasi):
            return os.path.abspath(olasi)

    # 4. çalışma dizini kontrolü.
    cwd_olasi = os.path.join(os.getcwd(), temiz)
    if os.path.exists(cwd_olasi):
        return os.path.abspath(cwd_olasi)

    return os.path.abspath(genisletilmis)


def _arka_planda_calistir(motor: OtonomKurtarmaMotoru) -> None:
    # otonom kurtarma motorunu çalıştırıp günlükleri aktarır.
    try:
        motor.calistir()
    except (KeyboardInterrupt, EOFError):
        print("\n")
        uyari_yaz("Kullanıcı tarafından durdurma sinyali alındı (Ctrl+C).")
    except Exception as e:
        hata_yaz(f"İşlem sırasında bir hata meydana geldi: {e}")


def interaktif_sihirbaz_baslat() -> None:
    # iki seçenekli terminal sihirbazı.
    while True:
        try:
            banner_yazdir()
            print("  1. Genel Tarama ve Şifre Çözümü")
            print("  2. Özel Tarama ve Şifre Çözümü")
            print("  0. Çıkış\n")

            secim = input("  Seçiminiz [0-2]: ").strip()

            if secim == "0":
                bilgi_yaz("rescat sonlandırıldı.")
                break

            elif secim == "1":
                # 1. genel tarama ve şifre çözümü.
                hedef_girdi = input("\n  Taranacak dizin yolu [Varsayılan: Mevcut dizin (.)]: ").strip()
                hedef = akilli_yol_coz(hedef_girdi) if hedef_girdi else os.getcwd()

                if not os.path.exists(hedef):
                    hata_yaz(f"Hedef dizin bulunamadı: {hedef}")
                    input("\n  Devam etmek için Enter'a basın...")
                    continue

                motor = OtonomKurtarmaMotoru(hedef=hedef, interaktif_sor=True)
                _arka_planda_calistir(motor)
                input("\n  Devam etmek için Enter'a basın...")

            elif secim == "2":
                # 2. özel tarama ve şifre çözümü.
                hedef_girdi = input("\n  Hedef dosya veya dizin yolu: ").strip()
                if not hedef_girdi:
                    uyari_yaz("Hedef dosya veya dizin yolu girmelisiniz!")
                    input("\n  Devam etmek için Enter'a basın...")
                    continue

                hedef = akilli_yol_coz(hedef_girdi)
                if not os.path.exists(hedef):
                    hata_yaz(f"Hedef bulunamadı: {hedef}")
                    input("\n  Devam etmek için Enter'a basın...")
                    continue

                uzanti_filtresi = None
                if os.path.isdir(hedef):
                    uz_girdi = input("  Filtrelenecek uzantı (örnek: .locked) [Varsayılan: Tümü]: ").strip()
                    if uz_girdi:
                        uzanti_filtresi = uz_girdi

                motor = OtonomKurtarmaMotoru(
                    hedef=hedef,
                    uzanti_filtresi=uzanti_filtresi,
                    interaktif_sor=True
                )
                _arka_planda_calistir(motor)
                input("\n  Devam etmek için Enter'a basın...")

            else:
                uyari_yaz("Geçersiz seçim! Lütfen 1, 2 veya 0 girin.")
                input("\n  Devam etmek için Enter'a basın...")

        except (KeyboardInterrupt, EOFError):
            print("\n")
            bilgi_yaz("Ana menüye dönüldü.")
            continue

