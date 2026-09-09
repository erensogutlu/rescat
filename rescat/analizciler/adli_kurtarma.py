import os
import sys
import glob
import shutil
import subprocess
from typing import List, Dict, Any, Optional
from rescat.cekirdek.dosya_tanimlayici import format_icerik_dogrula, sihirli_baytlardan_tur_tahmin_et


class AdliKurtarmaMotoru:
    """
    kriptografik olarak şifresi çözülemeyen durumlarda işletim sistemi gölge kopyalarını,
    btrfs/zfs anlık görüntülerini, geçici ofis dosyalarını ve sqlite wal/journal
    işlem kayıtlarını tarayarak veri kurtaran adli bilişim (dfır) motoru.
    """

    def __init__(self, cikti_dizini: Optional[str] = None) -> None:
        self.cikti_dizini = os.path.abspath(cikti_dizini or os.path.expanduser("~/Masaüstü/rescat_adli_kurtarma"))
        os.makedirs(self.cikti_dizini, exist_ok=True)

    def golge_kopya_ve_snapshot_tara(self, hedef_yol: str) -> List[Dict[str, Any]]:
        # anlık görüntü ve gölge kopyaları arar.
        bulunanlar: List[Dict[str, Any]] = []
        dosya_adi = os.path.basename(hedef_yol)

        if sys.platform.startswith("linux"):
            # 1. btrfs, zfs, timeshift ve snapper anlık görüntü dizinleri.
            olasi_snapshot_kokleri = [
                "/.snapshots",
                "/timeshift/snapshots",
                "/var/snapshots",
                os.path.expanduser("~/.snapshots")
            ]
            for kok in olasi_snapshot_kokleri:
                if os.path.isdir(kok):
                    try:
                        for kok_dizin, _, dosyalar in os.walk(kok):
                            if dosya_adi in dosyalar:
                                tam_yol = os.path.join(kok_dizin, dosya_adi)
                                bulunanlar.append({
                                    "tur": "Linux-Snapshot",
                                    "kaynak_yol": tam_yol,
                                    "boyut": os.path.getsize(tam_yol)
                                })
                    except Exception:
                        continue
        elif sys.platform.startswith("win"):
            # 2. windows gölge kopyaları (vss).
            try:
                cikti = subprocess.check_output(
                    ["vssadmin", "list", "shadows"],
                    stderr=subprocess.DEVNULL,
                    text=True,
                    timeout=5
                )
                if "Shadow Copy Volume Name" in cikti:
                    bulunanlar.append({
                        "tur": "Windows-VSS",
                        "detay": "VSS Anlık Görüntüleri mevcut. vssadmin veya diskshadow ile geri yüklenebilir."
                    })
            except Exception:
                pass

        return bulunanlar

    def gecici_ofis_ve_artik_dosyalari_tara(self, hedef_dizin: str) -> List[Dict[str, Any]]:
        # gizli, geçici ve yedek dosyaları arar.
        kurtarilanlar: List[Dict[str, Any]] = []
        if not os.path.isdir(hedef_dizin):
            hedef_dizin = os.path.dirname(hedef_dizin) or "."

        desenler = [
            "~*.tmp", "~*.docx", "~*.xlsx", "*.asd", ".~lock.*",
            ".goutputstream-*", "*.bak", "*.old", "*_backup.*"
        ]

        for d in desenler:
            for eslesme in glob.glob(os.path.join(hedef_dizin, d)):
                if os.path.isfile(eslesme):
                    try:
                        boyut = os.path.getsize(eslesme)
                        if boyut > 64:
                            with open(eslesme, "rb") as f:
                                ilk_bayt = f.read(512)
                            tur = sihirli_baytlardan_tur_tahmin_et(ilk_bayt)
                            kurtarilanlar.append({
                                "tur": "Gecici-Ofis-Artigi",
                                "dosya": eslesme,
                                "boyut": boyut,
                                "tahmin_edilen_tur": tur or "bilinmeyen"
                            })
                    except Exception:
                        continue

        return kurtarilanlar

    def sqlite_wal_ve_journal_kurtar(self, db_yolu: str) -> List[Dict[str, Any]]:
        # sqlite wal ve günlük artıklarını ayıklar.
        kurtarilanlar: List[Dict[str, Any]] = []
        kok, _ = os.path.splitext(db_yolu)
        adaylar = [f"{db_yolu}-wal", f"{db_yolu}-journal", f"{kok}.db-wal", f"{kok}.db-journal"]

        for aday in adaylar:
            if os.path.isfile(aday) and os.path.getsize(aday) > 32:
                try:
                    with open(aday, "rb") as f:
                        veri = f.read()
                    # sqlite wal sihirli baytı kontrolü.
                    if veri.startswith(b"\x37\x7f\x06\x82") or veri.startswith(b"\x37\x7f\x06\x83") or b"SQLite format 3" in veri:
                        hedef = os.path.join(self.cikti_dizini, f"kurtarilan_{os.path.basename(aday)}")
                        shutil.copy2(aday, hedef)
                        kurtarilanlar.append({
                            "tur": "SQLite-WAL/Journal",
                            "kaynak": aday,
                            "hedef": hedef,
                            "boyut": len(veri)
                        })
                except Exception:
                    continue

        return kurtarilanlar

    def tam_adli_kurtarma_yurut(self, hedef_yol: str) -> Dict[str, Any]:
        hedef_yol = os.path.abspath(hedef_yol)
        hedef_dizin = hedef_yol if os.path.isdir(hedef_yol) else os.path.dirname(hedef_yol)

        snapshotlar = self.golge_kopya_ve_snapshot_tara(hedef_yol)
        gecici_dosyalar = self.gecici_ofis_ve_artik_dosyalari_tara(hedef_dizin)
        wal_dosyalari = self.sqlite_wal_ve_journal_kurtar(hedef_yol)

        return {
            "hedef": hedef_yol,
            "cikti_dizini": self.cikti_dizini,
            "snapshot_ve_golgeler": snapshotlar,
            "gecici_ofis_artiklari": gecici_dosyalar,
            "sqlite_loglari": wal_dosyalari,
            "toplam_kurtarilabilir_oge": len(snapshotlar) + len(gecici_dosyalar) + len(wal_dosyalari)
        }
