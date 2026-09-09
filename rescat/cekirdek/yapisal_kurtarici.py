import os
import struct
import zlib
import zipfile
import io
from typing import Dict, List, Any, Optional, Tuple
from rescat.cekirdek.dosya_tanimlayici import sihirli_baytlardan_tur_tahmin_et, format_icerik_dogrula
from rescat.cekirdek.entropi import kayan_pencere_entropisi


class YapisalKurtarmaMotoru:
    """
    askeri standartta (aes-256, chacha20) kismi veya baslik sifrelemesine
    maruz kalmis yapisal dosyalar (zıp, docx, xlsx, sqlite, pdf vb.) icin
    derin yapisal veri kurtarma ve rekonstrüksiyon motoru.
    """

    def __init__(
        self,
        kuru_calistirma: bool = False,
        cikti_dizini: Optional[str] = None,
        yedek_al: bool = True,
        hedef_cikti_dizini: Optional[str] = None
    ) -> None:
        self.kuru_calistirma: bool = kuru_calistirma
        self.cikti_dizini: Optional[str] = cikti_dizini or hedef_cikti_dizini
        self.hedef_cikti_dizini: Optional[str] = self.cikti_dizini
        self.yedek_al: bool = yedek_al

    def sifreli_siniri_tespit_et(self, veri: bytes, blok_boyutu: int = 4096) -> int:
        """
        dosyanin basindaki sifreli yuksek entropili bolgenin nerede bittigini tespit et.
        0 ile len(veri) arasinda saglam govdenin basladigi bayt ofsetini dondurur.
        """
        toplam = len(veri)
        if toplam <= blok_boyutu:
            return toplam

        for ofset in range(0, toplam - blok_boyutu, blok_boyutu):
            blok = veri[ofset:ofset + blok_boyutu]
            # entropi veya bayt frekansı kontrolü.
            frekans = {}
            for b in blok:
                frekans[b] = frekans.get(b, 0) + 1
            # bölgede düşük entropili baytlar yoğunsa şifreleme bitmiştir.
            sifir_orani = frekans.get(0, 0) / len(blok)
            if sifir_orani > 0.15 or len(frekans) < 180:
                return ofset

        return toplam

    # -------------------------------------------------------------------------
    # 1. zip, docx ve xlsx arşiv kurtarıcı.
    # -------------------------------------------------------------------------
    def zip_arsiv_kurtar(self, dosya_yolu: str, hedef_cikti: Optional[str] = None) -> Dict[str, Any]:
        """
        ılk baytlari veya basligi sifrelenmis zıp / office (docx, xlsx, pptx)
        dosyalarinin kuyrugundaki central directory (eocd) yapilarini tarayarak
        saglam dosyalari ayristirir ve yeni bir gecerli zıp arsivi insa eder.
        """
        if not os.path.exists(dosya_yolu):
            return {"basarili": False, "hata": "Dosya bulunamadi"}

        try:
            with open(dosya_yolu, "rb") as f:
                ham_veri = f.read()

            toplam_boyut = len(ham_veri)
            if toplam_boyut < 64:
                return {"basarili": False, "hata": "Dosya boyutu cok kucuk"}

            # eocd işaretçisini arar.
            eocd_imza = b"PK\x05\x06"
            eocd_ofset = ham_veri.rfind(eocd_imza)

            kurtarilan_dosyalar: List[Dict[str, Any]] = []
            yeni_zip_bellek = io.BytesIO()

            with zipfile.ZipFile(yeni_zip_bellek, "w", zipfile.ZIP_DEFLATED) as hedef_zip:
                # 1. yöntem: eocd ve merkezi dizin sağlamsa.
                cd_imza = b"PK\x01\x02"
                cd_ofset = 0
                while True:
                    cd_ofset = ham_veri.find(cd_imza, cd_ofset)
                    if cd_ofset == -1:
                        break

                    if cd_ofset + 46 <= toplam_boyut:
                        # merkezi dizin başlığını ayrıştırır.
                        baslik = ham_veri[cd_ofset:cd_ofset + 46]
                        (
                            _, _, _, _, sikistirma_yontemi,
                            _, _, crc32, sikistirilmis_boyut,
                            orijinal_boyut, dosya_adi_uzunlugu,
                            ekstra_uzunluk, yorum_uzunlugu,
                            _, _, _, yerel_baslik_ofseti
                        ) = struct.unpack("<4sHHHHHHIIIHHHHHII", baslik)

                        dosya_adi_baslangic = cd_ofset + 46
                        dosya_adi_bitis = dosya_adi_baslangic + dosya_adi_uzunlugu
                        dosya_adi = ham_veri[dosya_adi_baslangic:dosya_adi_bitis].decode("utf-8", errors="ignore")

                        # yerel başlıktan veri bölgesine ulaşır.
                        yerel_ekstra = ekstra_uzunluk
                        if yerel_baslik_ofseti + 30 <= toplam_boyut and ham_veri[yerel_baslik_ofseti:yerel_baslik_ofseti + 4] == b"PK\x03\x04":
                            try:
                                yerel_ekstra = struct.unpack("<H", ham_veri[yerel_baslik_ofseti + 28:yerel_baslik_ofseti + 30])[0]
                            except Exception:
                                pass

                        veri_baslangici = yerel_baslik_ofseti + 30 + dosya_adi_uzunlugu + yerel_ekstra
                        veri_bitisi = veri_baslangici + sikistirilmis_boyut

                        if veri_bitisi <= toplam_boyut and sikistirilmis_boyut > 0:
                            ham_icerik = ham_veri[veri_baslangici:veri_bitisi]
                            try:
                                if sikistirma_yontemi == 0:  # depolanmış veri.
                                    cozulmus = ham_icerik
                                elif sikistirma_yontemi == 8:  # sıkıştırılmış veri.
                                    cozulmus = zlib.decompress(ham_icerik, -15)
                                else:
                                    cozulmus = ham_icerik

                                if len(cozulmus) > 0:
                                    hedef_zip.writestr(dosya_adi, cozulmus)
                                    kurtarilan_dosyalar.append({
                                        "dosya_adi": dosya_adi,
                                        "boyut": len(cozulmus),
                                        "metot": "Central-Directory"
                                    })
                            except Exception:
                                pass

                    cd_ofset += 4

                # 2. yöntem: ham yerel başlıkları tarar.
                if not kurtarilan_dosyalar:
                    lh_imza = b"PK\x03\x04"
                    lh_ofset = 0
                    while True:
                        lh_ofset = ham_veri.find(lh_imza, lh_ofset)
                        if lh_ofset == -1:
                            break

                        if lh_ofset + 30 <= toplam_boyut:
                            lh_baslik = ham_veri[lh_ofset:lh_ofset + 30]
                            (
                                _, _, _, sikistirma,
                                _, _, crc, sikis_b,
                                orj_b, ad_uzunlugu, ek_uzunluk
                            ) = struct.unpack("<4sHHHHHIIIHH", lh_baslik)

                            ad_bas = lh_ofset + 30
                            ad = ham_veri[ad_bas:ad_bas + ad_uzunlugu].decode("utf-8", errors="ignore")
                            veri_bas = ad_bas + ad_uzunlugu + ek_uzunluk
                            veri_son = veri_bas + sikis_b

                            if 0 < sikis_b <= (toplam_boyut - veri_bas) and ad:
                                try:
                                    sikis_veri = ham_veri[veri_bas:veri_son]
                                    if sikistirma == 8:
                                        acilan = zlib.decompress(sikis_veri, -15)
                                    else:
                                        acilan = sikis_veri
                                    hedef_zip.writestr(ad, acilan)
                                    kurtarilan_dosyalar.append({
                                        "dosya_adi": ad,
                                        "boyut": len(acilan),
                                        "metot": "Local-Header"
                                    })
                                except Exception:
                                    pass

                        lh_ofset += 4

            if not kurtarilan_dosyalar:
                return {
                    "basarili": False,
                    "hata": "Arsiv icinde saglam dosya kaydi bulunamadi (tamamen ezilmis olabilir)"
                }

            cikti_yolu = hedef_cikti or (dosya_yolu + ".kurtarildi.zip")
            if not self.kuru_calistirma:
                with open(cikti_yolu, "wb") as cikti_f:
                    cikti_f.write(yeni_zip_bellek.getvalue())

            return {
                "basarili": True,
                "kurtarma_turu": "ZIP/Office Yapısal Rekonstrüksiyon",
                "kaynak_dosya": dosya_yolu,
                "cikti_dosya": cikti_yolu,
                "hedef_yol": cikti_yolu,
                "kurtarilan_ic_dosya_sayisi": len(kurtarilan_dosyalar),
                "kurtarilan_dosyalar": kurtarilan_dosyalar,
                "kuru_calistirma": self.kuru_calistirma
            }

        except Exception as e:
            return {"basarili": False, "hata": str(e)}

    # -------------------------------------------------------------------------
    # 2. sqlite veritabanı leaf sayfa kurtarıcı.
    # -------------------------------------------------------------------------
    def sqlite_yapraklari_kurtar(
        self,
        dosya_yolu: str,
        sayfa_boyutu: int = 4096,
        hedef_cikti: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        ılk 100 baytlik basligi veya page 1'i aes-256 ile sifrelenmis sqlite
        veritabanlarinda, geriye kalan saglam leaf b-tree (0x0d) sayfalarini
        bularak temiz bir sqlite veritabanina veya ham kayit dokumune kurtarir.
        """
        if not os.path.exists(dosya_yolu):
            return {"basarili": False, "hata": "Dosya bulunamadi"}

        try:
            with open(dosya_yolu, "rb") as f:
                ham_veri = f.read()

            toplam_boyut = len(ham_veri)
            if toplam_boyut < sayfa_boyutu:
                return {"basarili": False, "hata": "Veritabani boyutu bir sayfadan kucuk"}

            bulunan_sayfa_sayisi = 0
            kurtarilan_metin_kayitlari: List[str] = []

            # 4096 bayt hizalı sayfaları tarar.
            for ofset in range(0, toplam_boyut - sayfa_boyutu + 1, sayfa_boyutu):
                sayfa = ham_veri[ofset:ofset + sayfa_boyutu]
                sayfa_tipi = sayfa[0]

                # 0x0d: b-tree leaf sayfası tespiti.
                if sayfa_tipi == 0x0D:
                    bulunan_sayfa_sayisi += 1
                    hucre_sayisi = int.from_bytes(sayfa[3:5], "big")
                    if 0 < hucre_sayisi < 1000:
                        # hücre içindeki metin kalıntılarını ayıklar.
                        # metin alanları utf-8 olarak ayrıştırılır.
                        import re
                        metinler = re.findall(rb"[\x20-\x7e\xc0-\xff]{4,}", sayfa[8:])
                        for m in metinler:
                            try:
                                cozum = m.decode("utf-8", errors="ignore").strip()
                                if len(cozum) >= 4 and cozum not in kurtarilan_metin_kayitlari:
                                    kurtarilan_metin_kayitlari.append(cozum)
                            except Exception:
                                pass

            # kurtarılan kayıtları adli döküm olarak yazar.
            cikti_yolu = hedef_cikti or (dosya_yolu + ".kurtarildi.db")
            dokum_yolu = dosya_yolu + ".kurtarilan_veriler.txt"

            if not self.kuru_calistirma:
                # standart başlıkla onarım denemesi.
                standart_sqlite_basligi = (
                    b"SQLite format 3\x00\x10\x00\x01\x01\x00@  \x00\x00\x00\x01"
                    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
                )
                onarilmis_db_verisi = standart_sqlite_basligi + ham_veri[len(standart_sqlite_basligi):]
                with open(cikti_yolu, "wb") as out_f:
                    out_f.write(onarilmis_db_verisi)

                # ham sayfa verilerini metin dökümü olarak kaydeder.
                if kurtarilan_metin_kayitlari:
                    with open(dokum_yolu, "w", encoding="utf-8") as dokum_f:
                        dokum_f.write(f"# RESCAT SQLite Adli B-Tree Leaf Kayit Dokumu\n")
                        dokum_f.write(f"# Kaynak: {dosya_yolu}\n")
                        dokum_f.write(f"# Kurtarilan Leaf Sayfa Sayisi: {bulunan_sayfa_sayisi}\n")
                        dokum_f.write(f"# Toplam Kayit: {len(kurtarilan_metin_kayitlari)}\n\n")
                        for idx, kayit in enumerate(kurtarilan_metin_kayitlari, 1):
                            dokum_f.write(f"[{idx}] {kayit}\n")

            return {
                "basarili": bulunan_sayfa_sayisi > 0 or len(kurtarilan_metin_kayitlari) > 0,
                "kurtarma_turu": "SQLite B-Tree Leaf Page Carving",
                "kaynak_dosya": dosya_yolu,
                "cikti_dosya": cikti_yolu,
                "hedef_yol": cikti_yolu,
                "dokum_dosya": dokum_yolu if not self.kuru_calistirma else None,
                "kurtarilan_leaf_sayfa_sayisi": bulunan_sayfa_sayisi,
                "cikartilan_metin_kayit_sayisi": len(kurtarilan_metin_kayitlari),
                "ornek_kayitlar": kurtarilan_metin_kayitlari[:15],
                "kuru_calistirma": self.kuru_calistirma
            }

        except Exception as e:
            return {"basarili": False, "hata": str(e)}

    # -------------------------------------------------------------------------
    # 3. pdf akış kurtarıcı ve yapılandırıcı.
    # -------------------------------------------------------------------------
    def pdf_akis_kurtar(self, dosya_yolu: str, hedef_cikti: Optional[str] = None) -> Dict[str, Any]:
        """
        ılk baytlari (%pdf basligi) ezilmis veya kismi sifrelenmis pdf
        dosyalarinda govdedeki saglam 'stream...endstream' veri bloklarini
        ve sayfalarini toplayarak gecerli bir pdf olarak onarir.
        """
        if not os.path.exists(dosya_yolu):
            return {"basarili": False, "hata": "Dosya bulunamadi"}

        try:
            with open(dosya_yolu, "rb") as f:
                ham_veri = f.read()

            import re
            stream_bloklari = list(re.finditer(rb"stream[\r\n]+([\s\S]*?)[\r\n]+endstream", ham_veri))

            kurtarilan_akis_sayisi = 0
            cikartilan_metinler: List[str] = []

            for eslesme in stream_bloklari:
                akis_verisi = eslesme.group(1)
                kurtarilan_akis_sayisi += 1
                try:
                    # flatedecode akışını deşifre eder.
                    acilan = zlib.decompress(akis_verisi)
                    metin_parcalari = re.findall(rb"\((.*?)\)[\s]*Tj", acilan)
                    for mp in metin_parcalari:
                        metin = mp.decode("latin1", errors="ignore").strip()
                        if len(metin) >= 3:
                            cikartilan_metinler.append(metin)
                except Exception:
                    pass

            # standart pdf başlığı ekler.
            standart_pdf_basligi = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n"
            if not ham_veri.startswith(b"%PDF"):
                kurtarilmis_pdf = standart_pdf_basligi + ham_veri[len(standart_pdf_basligi):]
            else:
                kurtarilmis_pdf = ham_veri

            if kurtarilan_akis_sayisi == 0 and len(cikartilan_metinler) == 0:
                return {"basarili": False, "hata": "PDF akış veya nesne yapısı bulunamadı"}

            cikti_yolu = hedef_cikti or (dosya_yolu + ".kurtarildi.pdf")
            dokum_yolu = dosya_yolu + ".kurtarilan_metinler.txt"

            if not self.kuru_calistirma:
                with open(cikti_yolu, "wb") as out_f:
                    out_f.write(kurtarilmis_pdf)

                if cikartilan_metinler:
                    with open(dokum_yolu, "w", encoding="utf-8") as dokum_f:
                        dokum_f.write(f"# RESCAT PDF Carved Metin Dokumu\n")
                        dokum_f.write(f"# Kaynak: {dosya_yolu}\n")
                        dokum_f.write(f"# Kurtarilan Stream Sayisi: {kurtarilan_akis_sayisi}\n\n")
                        for idx, txt in enumerate(cikartilan_metinler, 1):
                            dokum_f.write(f"[{idx}] {txt}\n")

            return {
                "basarili": True,
                "kurtarma_turu": "PDF Stream & Object Reconstruction",
                "kaynak_dosya": dosya_yolu,
                "cikti_dosya": cikti_yolu,
                "hedef_yol": cikti_yolu,
                "dokum_dosya": dokum_yolu if not self.kuru_calistirma else None,
                "kurtarilan_stream_nesnesi": kurtarilan_akis_sayisi,
                "cikartilan_metin_sayisi": len(cikartilan_metinler),
                "ornek_metinler": cikartilan_metinler[:10],
                "kuru_calistirma": self.kuru_calistirma
            }

        except Exception as e:
            return {"basarili": False, "hata": str(e)}

    # -------------------------------------------------------------------------
    # 4. mp4, mov ve m4v video kurtarıcı.
    # -------------------------------------------------------------------------
    def mp4_video_kurtar(self, dosya_yolu: str, hedef_cikti: Optional[str] = None) -> Dict[str, Any]:
        """
        başlığı veya ilk 1-4 mb'ı şifrelenmiş mp4 / mov / m4v video dosyalarında
        dosya kuyruğundaki veya gövdesindeki 'moov' (metaveri indeksi) atomunu tespit eder,
        standart ftyp başlığı ile birleştirip oynatılabilir mp4 dosyası inşa eder.
        """
        if not os.path.exists(dosya_yolu):
            return {"basarili": False, "hata": "Dosya bulunamadı"}

        try:
            with open(dosya_yolu, "rb") as f:
                ham_veri = f.read()

            toplam_boyut = len(ham_veri)
            if toplam_boyut < 128:
                return {"basarili": False, "hata": "Dosya boyutu video için çok küçük"}

            # moov atomunu arar.
            moov_ofset = ham_veri.rfind(b"moov")
            if moov_ofset == -1:
                moov_ofset = ham_veri.find(b"moov")

            if moov_ofset == -1 or moov_ofset < 4:
                return {"basarili": False, "hata": "moov atomu (video metaveri tablosu) bulunamadı"}

            # moov atomu başlangıç ofseti hesabı.
            atom_baslangic = moov_ofset - 4
            atom_boyutu = struct.unpack(">I", ham_veri[atom_baslangic:atom_baslangic + 4])[0]

            if atom_boyutu < 8 or atom_baslangic + atom_boyutu > toplam_boyut:
                moov_verisi = ham_veri[atom_baslangic:]
                gercek_boyut = len(moov_verisi)
                moov_verisi = struct.pack(">I", gercek_boyut) + b"moov" + moov_verisi[8:]
            else:
                moov_verisi = ham_veri[atom_baslangic:atom_baslangic + atom_boyutu]

            standart_ftyp = b"\x00\x00\x00\x20ftypisom\x00\x00\x02\x00isomiso2mp41"

            # mdat atomunu ve video verisini ayıklar.
            mdat_ofset = ham_veri.find(b"mdat")
            if mdat_ofset != -1 and mdat_ofset >= 4:
                mdat_baslangic = mdat_ofset - 4
                mdat_verisi = ham_veri[mdat_baslangic:atom_baslangic] if atom_baslangic > mdat_baslangic else ham_veri[mdat_baslangic:]
            else:
                saglam_ofset = self.sifreli_siniri_tespit_et(ham_veri[:min(1048576, toplam_boyut)])
                ham_akisi = ham_veri[saglam_ofset:atom_baslangic]
                mdat_verisi = struct.pack(">I", len(ham_akisi) + 8) + b"mdat" + ham_akisi

            kurtarilmis_video = standart_ftyp + moov_verisi + mdat_verisi

            cikti_yolu = hedef_cikti or (dosya_yolu + ".kurtarildi.mp4")
            if not self.kuru_calistirma:
                with open(cikti_yolu, "wb") as out_f:
                    out_f.write(kurtarilmis_video)

            return {
                "basarili": True,
                "kurtarma_turu": "MP4/MOV Fast-Start Moov Reconstruction",
                "kaynak_dosya": dosya_yolu,
                "cikti_dosya": cikti_yolu,
                "hedef_yol": cikti_yolu,
                "moov_boyutu": len(moov_verisi),
                "kurtarilan_boyut": len(kurtarilmis_video),
                "kuru_calistirma": self.kuru_calistirma
            }

        except Exception as e:
            return {"basarili": False, "hata": str(e)}

    # -------------------------------------------------------------------------
    # 5. jpeg resim başlık onarıcı ve kurtarıcı.
    # -------------------------------------------------------------------------
    def jpeg_resim_kurtar(self, dosya_yolu: str, hedef_cikti: Optional[str] = None) -> Dict[str, Any]:
        """
        ilk baytları veya exıf/jfıf başlığı şifrelenmiş jpeg dosyalarında
        start of scan (sos - 0xffda) veya quantization tablosunu (0xffdb) bularak
        standart jfıf başlığı enjekte eder ve görüntüyü kurtarır.
        """
        if not os.path.exists(dosya_yolu):
            return {"basarili": False, "hata": "Dosya bulunamadı"}

        try:
            with open(dosya_yolu, "rb") as f:
                ham_veri = f.read()

            toplam_boyut = len(ham_veri)
            if toplam_boyut < 64:
                return {"basarili": False, "hata": "Dosya boyutu çok küçük"}

            # sos veya dqt belirteçlerini arar.
            sos_ofset = ham_veri.find(b"\xFF\xDA")
            dqt_ofset = ham_veri.find(b"\xFF\xDB")

            if sos_ofset == -1 and dqt_ofset == -1:
                return {"basarili": False, "hata": "JPEG akış belirteçleri (SOS/DQT) bulunamadı"}

            standart_jpeg_basligi = (
                b"\xFF\xD8"  # soi başlangıcı.
                b"\xFF\xE0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00"  # jfif app0 başlığı.
            )

            if dqt_ofset != -1 and dqt_ofset < 2048:
                kurtarilmis_resim = standart_jpeg_basligi + ham_veri[dqt_ofset:]
            elif sos_ofset != -1:
                standart_tablolar = (
                    b"\xFF\xDB\x00C\x00\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07\t\t\x08\n\x0c\x14\r\x0c\x0b\x0b\x0c\x19\x12\x13\x0f\x14\x1d\x1a\x1f\x1e\x1d\x1a\x1c\x1c $.' \",#\x1c\x1c(7),01444\x1f'9=82<.342"
                    b"\xFF\xC0\x00\x11\x08\x03\x00\x04\x00\x03\x01\"\x00\x02\x11\x01\x03\x11\x01"
                )
                kurtarilmis_resim = standart_jpeg_basligi + standart_tablolar + ham_veri[sos_ofset:]
            else:
                kurtarilmis_resim = standart_jpeg_basligi + ham_veri[16:]

            if not kurtarilmis_resim.endswith(b"\xFF\xD9"):
                kurtarilmis_resim += b"\xFF\xD9"

            gecerli, _ = format_icerik_dogrula(kurtarilmis_resim, "jpg")
            if not gecerli:
                return {"basarili": False, "hata": "Kurtarılan JPEG verisi geçerli görüntü yapısı içermiyor"}

            cikti_yolu = hedef_cikti or (dosya_yolu + ".kurtarildi.jpg")
            if not self.kuru_calistirma:
                with open(cikti_yolu, "wb") as out_f:
                    out_f.write(kurtarilmis_resim)

            return {
                "basarili": True,
                "kurtarma_turu": "JPEG Header & Table Reconstruction",
                "kaynak_dosya": dosya_yolu,
                "cikti_dosya": cikti_yolu,
                "hedef_yol": cikti_yolu,
                "kurtarilan_boyut": len(kurtarilmis_resim),
                "kuru_calistirma": self.kuru_calistirma
            }

        except Exception as e:
            return {"basarili": False, "hata": str(e)}

    # -------------------------------------------------------------------------
    # genel otonom yapısal kurtarıcı dağıtıcı.
    # -------------------------------------------------------------------------
    def otonom_yapisal_kurtar(self, dosya_yolu: str) -> Dict[str, Any]:
        """
        dosya uzantisina veya dosya sonundaki gostergelere gore
        en uygun derin yapisal kurtarma algoritmasini otomatik calistirir.
        """
        uzanti = os.path.splitext(dosya_yolu)[1].lower()

        if uzanti in (".zip", ".docx", ".xlsx", ".pptx", ".jar", ".odt", ".ods"):
            return self.zip_arsiv_kurtar(dosya_yolu)
        elif uzanti in (".db", ".sqlite", ".sqlite3", ".sqlitedb"):
            return self.sqlite_yapraklari_kurtar(dosya_yolu)
        elif uzanti in (".pdf",):
            return self.pdf_akis_kurtar(dosya_yolu)
        elif uzanti in (".mp4", ".mov", ".m4v", ".avi", ".mkv"):
            return self.mp4_video_kurtar(dosya_yolu)
        elif uzanti in (".jpg", ".jpeg", ".jfif"):
            return self.jpeg_resim_kurtar(dosya_yolu)

        elif uzanti in (".vmdk", ".vhd", ".vhdx", ".qcow2"):
            return self.vmdk_disk_kurtar(dosya_yolu)

        # uzantı bilinmiyorsa dosya içeriğine bakar.
        try:
            boyut = os.path.getsize(dosya_yolu)
            with open(dosya_yolu, "rb") as f:
                f.seek(max(0, boyut - 2048))
                kuyruk = f.read(min(2048, boyut))
            if b"PK\x05\x06" in kuyruk:
                return self.zip_arsiv_kurtar(dosya_yolu)
            elif b"%%EOF" in kuyruk:
                return self.pdf_akis_kurtar(dosya_yolu)
            elif b"moov" in kuyruk:
                return self.mp4_video_kurtar(dosya_yolu)
            elif b"# Disk DescriptorFile" in kuyruk or b"KDMV" in kuyruk:
                return self.vmdk_disk_kurtar(dosya_yolu)
        except Exception:
            pass

        return {"basarili": False, "hata": f"Desteklenmeyen veya yapisal olmayan format: {uzanti}"}

    # -------------------------------------------------------------------------
    # vmdk ve sanal disk onarımı (esxi kurtarma).
    # -------------------------------------------------------------------------
    def vmdk_disk_kurtar(self, dosya_yolu: str) -> Dict[str, Any]:
        """
        esxiargs, babuk ve cheerscrypt tarafindan basligi veya aralikli bloklari
        sifrelenen vmware esxi (.vmdk / -flat.vmdk) sanal disklerini analiz eder.
        flat veri dosyasindaki ntfs/ext4 partisyon sektorlerini tespit edip
        calisabilir yeni bir vmdk tanimlayici (descriptor) dosyasi insa eder.
        """
        try:
            dosya_adi = os.path.basename(dosya_yolu)
            boyut = os.path.getsize(dosya_yolu)
            sektor_sayisi = boyut // 512

            # flat dosyasından vmdk adını belirler.
            if "-flat.vmdk" in dosya_adi:
                flat_adi = dosya_adi
                descriptor_adi = dosya_adi.replace("-flat.vmdk", ".vmdk")
            else:
                flat_adi = dosya_adi
                descriptor_adi = dosya_adi + ".repaired.vmdk"

            hedef_dizin = self.hedef_cikti_dizini or os.path.dirname(dosya_yolu) or "."
            os.makedirs(hedef_dizin, exist_ok=True)
            yeni_descriptor_yolu = os.path.join(hedef_dizin, descriptor_adi)

            # ntfs ve linux dosya sistemi sektörlerini arar.
            fs_turu = "Bilinmeyen"
            with open(dosya_yolu, "rb") as f:
                on_blok = f.read(min(65536, boyut))
                if b"NTFS    " in on_blok:
                    fs_turu = "NTFS (Windows)"
                elif b"\x53\xef" in on_blok:  # ext3 ve ext4 süperblok imzası.
                    fs_turu = "EXT4/EXT3 (Linux)"

            # standart esxi vmdk tanımlayıcı şablonu.
            descriptor_icerik = f"""# Disk DescriptorFile
version=1
encoding="UTF-8"
CID=fffffffe
parentCID=ffffffff
isNativeGeometry="no"
createType="vmfs"

# Extent description
RW {sektor_sayisi} VMFS "{flat_adi}" 0

# The Disk Data Base 
#DDB

ddb.adapterType = "lsilogic"
ddb.geometry.cylinders = "{max(1, sektor_sayisi // (255 * 63))}"
ddb.geometry.heads = "255"
ddb.geometry.sectors = "63"
ddb.longContentID = "1a2b3c4d5e6f708192a3b4c5d6e7f801"
ddb.virtualHWVersion = "14"
"""
            if not self.kuru_calistirma:
                with open(yeni_descriptor_yolu, "w", encoding="utf-8") as f_desc:
                    f_desc.write(descriptor_icerik)

            return {
                "basarili": True,
                "format": "vmdk",
                "dosya": dosya_yolu,
                "hedef_yol": yeni_descriptor_yolu,
                "tespit_edilen_fs": fs_turu,
                "sektor_sayisi": sektor_sayisi,
                "disk_boyutu_gb": round(boyut / (1024**3), 2)
            }
        except Exception as e:
            return {"basarili": False, "dosya": dosya_yolu, "hata": str(e)}

