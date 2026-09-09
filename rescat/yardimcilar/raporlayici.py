import json
import os
import time
from typing import Any, Dict, List, Optional, Tuple


class Raporlayici:
    # analiz sonuçlarını json, markdown ve html kaydeden sınıf.
    def __init__(self, vaka_adi: str = "ransomware_vakasi") -> None:
        # raporlayıcı başlangıç değişkenlerini atar.
        self.vaka_adi: str = vaka_adi
        self.olusturma_zamani: str = time.strftime("%Y-%m-%d %H:%M:%S")
        self.veriler: Dict[str, Any] = {
            "vaka_adi": self.vaka_adi,
            "olusturma_zamani": self.olusturma_zamani,
            "ozet": {},
            "tespit_edilen_fidye_notlari": [],
            "analiz_edilen_dosyalar": [],
            "kurtarilan_anahtarlar": [],
            "cozum_islemleri": []
        }

    def ozet_ekle(self, ozet_bilgisi: Dict[str, Any]) -> None:
        # vakaya dair üst seviye özeti ekler.
        self.veriler["ozet"].update(ozet_bilgisi)

    def fidye_notu_ekle(self, not_bilgisi: Dict[str, Any]) -> None:
        # tespit edilen fidye notu detayını ekler.
        self.veriler["tespit_edilen_fidye_notlari"].append(not_bilgisi)

    def dosya_analizi_ekle(self, dosya_bilgisi: Dict[str, Any]) -> None:
        # dosya analiz sonucunu listeye ekler.
        self.veriler["analiz_edilen_dosyalar"].append(dosya_bilgisi)

    def anahtar_ekle(self, anahtar_bilgisi: Dict[str, Any]) -> None:
        # kurtarılan anahtar bilgisini ekler.
        self.veriler["kurtarilan_anahtarlar"].append(anahtar_bilgisi)

    def cozum_ekle(self, cozum_bilgisi: Dict[str, Any]) -> None:
        # deşifreleme işlemi kaydını ekler.
        self.veriler["cozum_islemleri"].append(cozum_bilgisi)

    def adli_analiz_ekle(self, adli_analiz_bilgisi: Dict[str, Any]) -> None:
        # adli olay ve mitre att&ck analizini ekler.
        self.veriler["adli_analiz"] = adli_analiz_bilgisi

    def konsolda_rapor_goster(self) -> None:
        # raporu konsolda biçimlendirilmiş olarak gösterir.
        from rescat.yardimcilar.konsol import (
            baslik_yaz, tablo_satiri_yaz, bilgi_yaz, basari_yaz, uyari_yaz,
            RENK_YESIL, RENK_KIRMIZI, RENK_SIFIRLA, dengeli_bekle
        )

        baslik_yaz("RESCAT ADLİ OLAY VE KURTARMA RAPORU")
        tablo_satiri_yaz("Vaka Adı", self.vaka_adi)
        tablo_satiri_yaz("Rapor Tarihi", self.olusturma_zamani)
        tablo_satiri_yaz("Raporlama Modu", "Konsol İçi Canlı Görünüm (100% Çevrimdışı, Diske Yazılmaz)")

        dengeli_bekle(0.03)
        # 1. vaka özeti.
        if self.veriler.get("ozet"):
            baslik_yaz("1. Vaka ve Kurtarma Özeti")
            for k, v in self.veriler["ozet"].items():
                tablo_satiri_yaz(k, str(v))

        dengeli_bekle(0.03)
        # 2. fidye notları ve tehdit analizi.
        fidye_notlari = self.veriler.get("tespit_edilen_fidye_notlari", [])
        if fidye_notlari:
            baslik_yaz(f"2. Tespit Edilen Fidye Notları ({len(fidye_notlari)})")
            for idx, fn in enumerate(fidye_notlari, start=1):
                bilgi_yaz(f"Fidye Notu #{idx}: {fn.get('dosya_yolu', 'Bilinmiyor')}")
                if fn.get("bitcoin_cuzdanlari"):
                    tablo_satiri_yaz("  Bitcoin Cüzdanları", ", ".join(fn["bitcoin_cuzdanlari"]))
                if fn.get("monero_cuzdanlari"):
                    tablo_satiri_yaz("  Monero Cüzdanları", ", ".join(fn["monero_cuzdanlari"]))
                if fn.get("tor_baglantilari"):
                    tablo_satiri_yaz("  Tor Bağlantıları", ", ".join(fn["tor_baglantilari"]))
                if fn.get("iletisim_epostalari"):
                    tablo_satiri_yaz("  İletişim E-postaları", ", ".join(fn["iletisim_epostalari"]))

        dengeli_bekle(0.03)
        # 3. kurtarılan anahtarlar.
        anahtarlar = self.veriler.get("kurtarilan_anahtarlar", [])
        if anahtarlar:
            baslik_yaz(f"3. Bellekten Kurtarılan Anahtarlar ({len(anahtarlar)})")
            for a in anahtarlar:
                basari_yaz(f"[{a.get('tur', 'Kripto')}] Anahtar: {a.get('deger', '')} (Kaynak: {a.get('kaynak', 'Bellek')})")

        dengeli_bekle(0.03)
        # 4. deşifreleme işlemleri.
        cozumler = self.veriler.get("cozum_islemleri", [])
        if cozumler:
            baslik_yaz(f"4. Şifre Çözüm ve Dosya Kurtarma Dökümü ({len(cozumler)})")
            for c in cozumler:
                durum = f"{RENK_YESIL}BAŞARILI{RENK_SIFIRLA}" if c.get("basarili") else f"{RENK_KIRMIZI}BAŞARISIZ{RENK_SIFIRLA}"
                dosya = os.path.basename(c.get("dosya_yolu", ""))
                algo = c.get("algoritma", "Bilinmiyor")
                tur = c.get("dogrulanan_tur", "-")
                tablo_satiri_yaz(f"[{durum}] {dosya}", f"Algoritma: {algo} | Çıktı Türü: {tur}")

        dengeli_bekle(0.03)
        # 5. adli olay analizi ve mitre att&ck.
        adli = self.veriler.get("adli_analiz")
        if adli:
            baslik_yaz("5. MITRE ATT&CK ve Adli Olay Bulguları")
            tablo_satiri_yaz("Genel Risk Seviyesi", str(adli.get("risk_seviyesi", "Bilinmiyor")))
            tablo_satiri_yaz("Toplam Tehdit Bulgusu", str(adli.get("toplam_bulgu", 0)))
            for b in adli.get("bulgular", []):
                uyari_yaz(f"[{b.get('mitre_id')}] {b.get('mitre_ad')} (Taktik: {b.get('taktik')}, Risk: {b.get('risk')})")


    def dosya_sha256_hesapla(self, dosya_yolu: str) -> Optional[str]:
        if not os.path.exists(dosya_yolu) or not os.path.isfile(dosya_yolu):
            return None
        try:
            import hashlib
            h = hashlib.sha256()
            with open(dosya_yolu, "rb") as f:
                while True:
                    blok = f.read(65536)
                    if not blok:
                        break
                    h.update(blok)
            return h.hexdigest()
        except Exception:
            return None

    def stix_bundle_olustur(self) -> Dict[str, Any]:
        """
        analiz ve kurtarma verilerini oasıs stıx 2.1 json standart bundle nesnesine donusturur.
        """
        import uuid
        bundle_id = f"bundle--{uuid.uuid4()}"
        nesneler: List[Dict[str, Any]] = []
        zaman_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        # 1. kimlik nesnesi.
        identity_id = f"identity--{uuid.uuid4()}"
        nesneler.append({
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": zaman_iso,
            "modified": zaman_iso,
            "name": "rescat Autonomous Forensics & Cryptanalysis Engine",
            "identity_class": "system"
        })

        # 2. zararlı yazılım nesnesi.
        zararli_adi = self.veriler.get("ozet", {}).get("Tespit Edilen Zararlı Ailesi") or "Ransomware.Generic"
        malware_id = f"malware--{uuid.uuid4()}"
        nesneler.append({
            "type": "malware",
            "spec_version": "2.1",
            "id": malware_id,
            "created": zaman_iso,
            "modified": zaman_iso,
            "name": str(zararli_adi),
            "is_family": True,
            "malware_types": ["ransomware"]
        })

        # 3. dosya ve gösterge nesneleri.
        for dosya in self.veriler.get("analiz_edilen_dosyalar", []):
            dosya_yolu = dosya.get("dosya_yolu") or dosya.get("dosya", "")
            sha256_hash = self.dosya_sha256_hesapla(dosya_yolu) if dosya_yolu else None

            indicator_id = f"indicator--{uuid.uuid4()}"
            pattern = f"[file:name = '{os.path.basename(dosya_yolu)}']"
            if sha256_hash:
                pattern = f"[file:hashes.'SHA-256' = '{sha256_hash}']"

            nesneler.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": indicator_id,
                "created": zaman_iso,
                "modified": zaman_iso,
                "name": f"Şifreli Dosya IOC: {os.path.basename(dosya_yolu)}",
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": zaman_iso
            })

            nesneler.append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": f"relationship--{uuid.uuid4()}",
                "created": zaman_iso,
                "modified": zaman_iso,
                "relationship_type": "indicates",
                "source_ref": indicator_id,
                "target_ref": malware_id
            })

        # 4. fidye notu göstergeleri.
        for fn in self.veriler.get("tespit_edilen_fidye_notlari", []):
            for btc in fn.get("bitcoin_cuzdanlari", []):
                nesneler.append({
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": f"indicator--{uuid.uuid4()}",
                    "created": zaman_iso,
                    "modified": zaman_iso,
                    "name": f"Ransomware BTC Cüzdanı: {btc}",
                    "pattern": f"[cryptocurrency-wallet:address = '{btc}']",
                    "pattern_type": "stix",
                    "valid_from": zaman_iso
                })
            for xmr in fn.get("monero_cuzdanlari", []):
                nesneler.append({
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": f"indicator--{uuid.uuid4()}",
                    "created": zaman_iso,
                    "modified": zaman_iso,
                    "name": f"Ransomware XMR Cüzdanı: {xmr}",
                    "pattern": f"[cryptocurrency-wallet:address = '{xmr}']",
                    "pattern_type": "stix",
                    "valid_from": zaman_iso
                })
            for tor in fn.get("tor_baglantilari", []):
                nesneler.append({
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": f"indicator--{uuid.uuid4()}",
                    "created": zaman_iso,
                    "modified": zaman_iso,
                    "name": f"Ransomware Tor Ödeme Portalı: {tor}",
                    "pattern": f"[url:value = '{tor}']",
                    "pattern_type": "stix",
                    "valid_from": zaman_iso
                })

        return {
            "type": "bundle",
            "id": bundle_id,
            "spec_version": "2.1",
            "objects": nesneler
        }

    def stix_olarak_kaydet(self, dosya_yolu: str) -> None:
        """
        stıx 2.1 bundle nesnesini json olarak diske kaydeder.
        """
        hedef_dizin = os.path.dirname(dosya_yolu)
        if hedef_dizin:
            os.makedirs(hedef_dizin, exist_ok=True)
        bundle = self.stix_bundle_olustur()
        with open(dosya_yolu, "w", encoding="utf-8") as f:
            json.dump(bundle, f, indent=4, ensure_ascii=False)

    def json_olarak_kaydet(self, dosya_yolu: str) -> None:
        # raporu json formatında diske yazar.
        hedef_dizin = os.path.dirname(dosya_yolu)
        if hedef_dizin:
            os.makedirs(hedef_dizin, exist_ok=True)
        with open(dosya_yolu, "w", encoding="utf-8") as dosya_nesnesi:
            json.dump(self.veriler, dosya_nesnesi, indent=4, ensure_ascii=False)

    def markdown_olarak_kaydet(self, dosya_yolu: str) -> None:
        # adli bilişim raporunu markdown olarak diske yazar.
        hedef_dizin = os.path.dirname(dosya_yolu)
        if hedef_dizin:
            os.makedirs(hedef_dizin, exist_ok=True)

        satirlar = [
            f"# rescat Olay Mudahale ve Ransomware Analiz Raporu",
            f"- **Vaka:** {self.vaka_adi}",
            f"- **Rapor Tarihi:** {self.olusturma_zamani}",
            f"",
            f"## 1. Vaka Ozeti",
        ]

        for anahtar_adi, deger in self.veriler["ozet"].items():
            satirlar.append(f"- **{anahtar_adi}:** {deger}")

        satirlar.append(f"\n## 2. Tespit Edilen Fidye Notlari ({len(self.veriler['tespit_edilen_fidye_notlari'])})")
        for fidye_notu in self.veriler["tespit_edilen_fidye_notlari"]:
            satirlar.append(f"### Dosya: `{fidye_notu.get('dosya_yolu', 'Bilinmiyor')}`")
            if "bitcoin_cuzdanlari" in fidye_notu and fidye_notu["bitcoin_cuzdanlari"]:
                satirlar.append(f"- **Bitcoin Adresleri:** {', '.join(fidye_notu['bitcoin_cuzdanlari'])}")
            if "monero_cuzdanlari" in fidye_notu and fidye_notu["monero_cuzdanlari"]:
                satirlar.append(f"- **Monero Adresleri:** {', '.join(fidye_notu['monero_cuzdanlari'])}")
            if "tor_baglantilari" in fidye_notu and fidye_notu["tor_baglantilari"]:
                satirlar.append(f"- **Tor Baglantilari:** {', '.join(fidye_notu['tor_baglantilari'])}")
            if "iletisim_epostalari" in fidye_notu and fidye_notu["iletisim_epostalari"]:
                satirlar.append(f"- **E-postalar:** {', '.join(fidye_notu['iletisim_epostalari'])}")

        satirlar.append(f"\n## 3. Kurtarilan veya Tespit Edilen Anahtarlar ({len(self.veriler['kurtarilan_anahtarlar'])})")
        for anahtar_kaydi in self.veriler["kurtarilan_anahtarlar"]:
            satirlar.append(f"- **Tur:** {anahtar_kaydi.get('tur', 'Bilinmiyor')} | **Deger:** `{anahtar_kaydi.get('deger', '')}` | **Kaynak:** {anahtar_kaydi.get('kaynak', '')}")

        satirlar.append(f"\n## 4. Desifreleme Islemleri ({len(self.veriler['cozum_islemleri'])})")
        for cozum in self.veriler["cozum_islemleri"]:
            durum = "Basarili" if cozum.get("basarili") else "Basarisiz"
            satirlar.append(f"- **Dosya:** `{cozum.get('dosya_yolu', '')}` | **Durum:** {durum} | **Algoritma:** {cozum.get('algoritma', '')}")

        if "adli_analiz" in self.veriler and self.veriler["adli_analiz"]:
            aa = self.veriler["adli_analiz"]
            satirlar.append(f"\n## 5. Adli Olay Analizi ve MITRE ATT&CK Bulgulari")
            satirlar.append(f"- **Genel Tehdit Risk Seviyesi:** {aa.get('risk_seviyesi', 'Bilinmiyor')}")
            satirlar.append(f"- **Toplam Tespit:** {aa.get('toplam_bulgu', 0)}")
            satirlar.append(f"\n### MITRE ATT&CK Teknikleri")
            for b in aa.get("bulgular", []):
                satirlar.append(f"- `[{b.get('mitre_id')}]` **{b.get('mitre_ad')}** | Taktik: {b.get('taktik')} | Risk: {b.get('risk')} | Kaynak: {b.get('kaynak')}")
                satirlar.append(f"  - *Tespit:* `{b.get('tespit')}`")

            satirlar.append(f"\n### Olay Mudahale Eylem Plani (NIST SP 800-61)")
            ep = aa.get("eylem_plani", {})
            satirlar.append("**Containment (Yalitma):**")
            for adim in ep.get("containment", []):
                satirlar.append(f"- {adim}")
            satirlar.append("**Eradication (Temizleme):**")
            for adim in ep.get("eradication", []):
                satirlar.append(f"- {adim}")
            satirlar.append("**Recovery (Kurtarma):**")
            for adim in ep.get("recovery", []):
                satirlar.append(f"- {adim}")

        with open(dosya_yolu, "w", encoding="utf-8") as dosya_nesnesi:
            dosya_nesnesi.write("\n".join(satirlar) + "\n")

    def html_olarak_kaydet(
        self,
        dosya_yolu: str,
        entropi_haritasi: Optional[List[Tuple[int, float]]] = None
    ) -> None:
        # adli bilişim raporunu html olarak diske yazar.
        hedef_dizin = os.path.dirname(dosya_yolu)
        if hedef_dizin:
            os.makedirs(hedef_dizin, exist_ok=True)

        # harita verildiyse svg çizgisi oluşturur.
        svg_cizgisi = ""
        svg_noktalari = []
        if entropi_haritasi and len(entropi_haritasi) > 1:
            genislik = 800
            yukseklik = 200
            maksimum_ofset = max(ofset for ofset, _ in entropi_haritasi) or 1

            for ofset, entropi in entropi_haritasi:
                x_koord = int((ofset / maksimum_ofset) * (genislik - 40)) + 20
                y_koord = int(yukseklik - 20 - (entropi / 8.0) * (yukseklik - 40))
                svg_noktalari.append(f"{x_koord},{y_koord}")

            nokta_dizesi = " ".join(svg_noktalari)
            svg_cizgisi = f"""
            <div style="background:#1e1e2f; padding:15px; border-radius:8px; margin-top:15px;">
                <h3 style="color:#00ffff; margin-top:0;">kayan pencere entropi grafigi (0.0 - 8.0 bit/bayt)</h3>
                <svg width="100%" height="220" viewbox="0 0 {genislik} {yukseklik}" style="overflow:visible;">
                    <!-- esik cizgisi 7.2 kirmizi -->
                    <line x1="20" y1="{int(yukseklik - 20 - (7.2/8.0)*(yukseklik - 40))}" x2="{genislik-20}" y2="{int(yukseklik - 20 - (7.2/8.0)*(yukseklik - 40))}" stroke="#ff4757" stroke-dasharray="4" stroke-width="2"/>
                    <text x="{genislik-140}" y="{int(yukseklik - 25 - (7.2/8.0)*(yukseklik - 40))}" fill="#ff4757" font-size="12">sifreli esik (7.2)</text>
                    <!-- veri egirisi -->
                    <polyline fill="none" stroke="#2ed573" stroke-width="2.5" points="{nokta_dizesi}" />
                </svg>
            </div>
            """

        html_govdesi = f"""<!doctype html>
<html lang="tr">
<head>
    <meta charset="utf-8">
    <title>rescat adli analiz raporu - {self.vaka_adi}</title>
    <style>
        body {{ font-family: 'segoe uı', tahoma, geneva, verdana, sans-serif; background: #0f111a; color: #f1f2f6; margin: 0; padding: 25px; }}
        .kart {{ background:  # 1a1c29; border: 1px solid #2f3542; border-radius: 8px; padding: 20px; margin-bottom: 20px; }}
        h1, h2, h3 {{ color:  # 00d2d3; }}
        .etiket {{ display: inline-block; background:  # ff4757; color: white; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 12px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ border: 1px solid  # 2f3542; padding: 10px; text-align: left; }}
        th {{ background:  # 2f3542; color: #00d2d3; }}
        .kod {{ font-family: monospace; background:  # 2f3542; padding: 2px 6px; border-radius: 4px; color: #ffa502; }}
    </style>
</head>
<body>
    <div class="kart">
        <h1>🛡 rescat Ransomware Olay Mudahale Raporu</h1>
        <p><strong>vaka adi:</strong> {self.vaka_adi} | <strong>rapor tarihi:</strong> {self.olusturma_zamani}</p>
    </div>

    <div class="kart">
        <h2>1. Vaka Ozeti</h2>
        <table>
            <tr><th>ozellik</th><th>deger</th></tr>
            {''.join(f'<tr><td>{k}</td><td>{v}</td></tr>' for k, v in self.veriler['ozet'].items())}
        </table>
        {svg_cizgisi}
    </div>

    <div class="kart">
        <h2>2. Tespit Edilen Fidye Notlari ({len(self.veriler['tespit_edilen_fidye_notlari'])})</h2>
        {''.join(f'''
        <div style="border-left: 4px solid #ff4757; padding-left: 10px; margin-bottom: 15px;">
            <p><strong>dosya:</strong> <span class="kod">{n.get('dosya_yolu', 'bilinmiyor')}</span></p>
            <p><strong>btc:</strong> {', '.join(n.get('bitcoin_cuzdanlari', [])) or 'yok'}</p>
            <p><strong>xmr:</strong> {', '.join(n.get('monero_cuzdanlari', [])) or 'yok'}</p>
            <p><strong>tor:</strong> {', '.join(n.get('tor_baglantilari', [])) or 'yok'}</p>
            <p><strong>e-posta:</strong> {', '.join(n.get('iletisim_epostalari', [])) or 'yok'}</p>
        </div>
        ''' for n in self.veriler['tespit_edilen_fidye_notlari'])}
    </div>

    <div class="kart">
        <h2>3. Kurtarilan Anahtarlar ({len(self.veriler['kurtarilan_anahtarlar'])})</h2>
        <table>
            <tr><th>tur</th><th>anahtar / deger</th><th>kaynak</th></tr>
            {''.join(f"<tr><td>{a.get('tur', '')}</td><td class='kod'>{a.get('deger', '')}</td><td>{a.get('kaynak', '')}</td></tr>" for a in self.veriler['kurtarilan_anahtarlar'])}
        </table>
    </div>

    <div class="kart">
        <h2>4. Desifreleme Islemleri ({len(self.veriler['cozum_islemleri'])})</h2>
        <table>
            <tr><th>dosya</th><th>durum</th><th>algoritma</th><th>dogrulanan tur</th></tr>
            {''.join(f"<tr><td class='kod'>{c.get('dosya_yolu', '')}</td><td style='color: {'#2ed573' if c.get('basarili') else '#ff4757'}'>{'basarili' if c.get('basarili') else 'basarisiz'}</td><td>{c.get('algoritma', '')}</td><td>{c.get('dogrulanan_tur', 'yok')}</td></tr>" for c in self.veriler['cozum_islemleri'])}
        </table>
    </div>
    {f'''
    <div class="kart">
        <h2>5. Adli Olay Analizi ve MITRE ATT&CK ({self.veriler["adli_analiz"].get("risk_seviyesi", "")})</h2>
        <p><strong>toplam tespit:</strong> {self.veriler["adli_analiz"].get("toplam_bulgu", 0)}</p>
        <table>
            <tr><th>mıtre ıd</th><th>teknik</th><th>taktik</th><th>risk</th><th>detay</th></tr>
            {''.join(f"<tr><td class='kod'>{b.get('mitre_id')}</td><td>{b.get('mitre_ad')}</td><td>{b.get('taktik')}</td><td style='color:#ff4757; font-weight:bold;'>{b.get('risk')}</td><td class='kod'>{b.get('tespit')}</td></tr>" for b in self.veriler["adli_analiz"].get("bulgular", []))}
        </table>
    </div>
    ''' if "adli_analiz" in self.veriler and self.veriler["adli_analiz"] else ''}
</body>
</html>
"""
        with open(dosya_yolu, "w", encoding="utf-8") as html_dosyasi:
            html_dosyasi.write(html_govdesi)
