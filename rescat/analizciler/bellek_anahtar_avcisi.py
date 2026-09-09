import os
import re
from typing import Dict, List, Set, Any, Optional
from rescat.cekirdek.entropi import shannon_entropisi_hesapla

# rsa pem özel anahtar deseni.
PEM_RSA_DESENI = rb"-----BEGIN (?:RSA )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA )?PRIVATE KEY-----"

# aes s-box tablosu.
AES_SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5e, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


def aes128_anahtar_genisletmesi_dogrula(aday_blok: bytes) -> bool:
    # aes-128 genişletilmiş anahtar çizelgesi kontrolü.
    if len(aday_blok) < 176:
        return False

    # ilk tur genişlemesini kontrol eder.
    kelime_3 = aday_blok[12:16]
    donmus_kelime = bytes([
        AES_SBOX[kelime_3[1]] ^ RCON[0],
        AES_SBOX[kelime_3[2]],
        AES_SBOX[kelime_3[3]],
        AES_SBOX[kelime_3[0]]
    ])

    hesaplanan_kelime_4 = bytes([
        aday_blok[0] ^ donmus_kelime[0],
        aday_blok[1] ^ donmus_kelime[1],
        aday_blok[2] ^ donmus_kelime[2],
        aday_blok[3] ^ donmus_kelime[3]
    ])

    return aday_blok[16:20] == hesaplanan_kelime_4


def aes256_anahtar_genisletmesi_dogrula(aday_blok: bytes) -> bool:
    # aes-256 genişletilmiş anahtar çizelgesi kontrolü.
    if len(aday_blok) < 240:
        return False

    # aes-256 anahtar çizelgesi 8. kelime doğrulaması.
    kelime_7 = aday_blok[28:32]
    donmus_kelime_7 = bytes([
        AES_SBOX[kelime_7[1]] ^ RCON[0],
        AES_SBOX[kelime_7[2]],
        AES_SBOX[kelime_7[3]],
        AES_SBOX[kelime_7[0]]
    ])

    hesaplanan_kelime_8 = bytes([
        aday_blok[0] ^ donmus_kelime_7[0],
        aday_blok[1] ^ donmus_kelime_7[1],
        aday_blok[2] ^ donmus_kelime_7[2],
        aday_blok[3] ^ donmus_kelime_7[3]
    ])

    if aday_blok[32:36] != hesaplanan_kelime_8:
        return False

    # aes-256 anahtar çizelgesi 12. kelime doğrulaması.
    kelime_11 = aday_blok[44:48]
    sub_kelime_11 = bytes([
        AES_SBOX[kelime_11[0]],
        AES_SBOX[kelime_11[1]],
        AES_SBOX[kelime_11[2]],
        AES_SBOX[kelime_11[3]]
    ])

    hesaplanan_kelime_12 = bytes([
        aday_blok[16] ^ sub_kelime_11[0],
        aday_blok[17] ^ sub_kelime_11[1],
        aday_blok[18] ^ sub_kelime_11[2],
        aday_blok[19] ^ sub_kelime_11[3]
    ])

    return aday_blok[48:52] == hesaplanan_kelime_12


# chacha20 ve salsa20 matris sabitleri.
CHACHA20_SABITI_32 = b"expand 32-byte k"
CHACHA20_SABITI_16 = b"expand 16-byte k"
SALSA20_SABITI_32 = b"expand 32-byte k"


def chacha20_matris_ara(ham_veri: bytes) -> List[Dict[str, Any]]:
    # bellekten chacha20 durum matrisi ile anahtar ve nonce çıkarır.
    bulunanlar: List[Dict[str, Any]] = []
    toplam = len(ham_veri)
    if toplam < 64:
        return bulunanlar

    # 32 baytlık chacha20 durum bloğu.
    ofset = 0
    while True:
        bulunan_ofset = ham_veri.find(CHACHA20_SABITI_32, ofset)
        if bulunan_ofset == -1:
            break
        if bulunan_ofset + 64 <= toplam:
            durum_blogu = ham_veri[bulunan_ofset:bulunan_ofset + 64]
            anahtar = durum_blogu[16:48]
            sayac_ve_nonce = durum_blogu[48:64]
            # entropi ve bayt çeşitliliği kontrolü.
            if len(set(anahtar)) >= 10:
                kayit = {
                    "tur": "ChaCha20-256",
                    "ofset": bulunan_ofset,
                    "anahtar_hex": anahtar.hex(),
                    "anahtar_baytlar": anahtar,
                    "sayac_ve_nonce_hex": sayac_ve_nonce.hex(),
                    "nonce_ietf_hex": sayac_ve_nonce[4:16].hex()
                }
                if not any(b["anahtar_hex"] == kayit["anahtar_hex"] for b in bulunanlar):
                    bulunanlar.append(kayit)
        ofset = bulunan_ofset + 1

    return bulunanlar


def salsa20_matris_ara(ham_veri: bytes) -> List[Dict[str, Any]]:
    # bellekten salsa20 durum matrisi ile anahtar ve nonce çıkarır.
    bulunanlar: List[Dict[str, Any]] = []
    toplam = len(ham_veri)
    if toplam < 64:
        return bulunanlar

    ofset = 0
    while True:
        # salsa20 başlangıç kelimesi kontrolü.
        bulunan_ofset = ham_veri.find(b"expa", ofset)
        if bulunan_ofset == -1:
            break

        if bulunan_ofset + 64 <= toplam:
            durum = ham_veri[bulunan_ofset:bulunan_ofset + 64]
            # 32 baytlık salsa20 anahtar matrisi kontrolü.
            if durum[20:24] == b"nd 3" and durum[40:44] == b"2-by" and durum[60:64] == b"te k":
                anahtar = durum[4:20] + durum[44:60]
                nonce = durum[24:32]
                sayac = durum[32:40]
                if len(set(anahtar)) >= 10:
                    kayit = {
                        "tur": "Salsa20-256",
                        "ofset": bulunan_ofset,
                        "anahtar_hex": anahtar.hex(),
                        "anahtar_baytlar": anahtar,
                        "nonce_hex": nonce.hex(),
                        "sayac_hex": sayac.hex()
                    }
                    if not any(b["anahtar_hex"] == kayit["anahtar_hex"] for b in bulunanlar):
                        bulunanlar.append(kayit)

            # 16 baytlık salsa20 anahtar matrisi kontrolü.
            elif durum[20:24] == b"nd 1" and durum[40:44] == b"6-by" and durum[60:64] == b"te k":
                anahtar = durum[4:20]
                nonce = durum[24:32]
                sayac = durum[32:40]
                if len(set(anahtar)) >= 8:
                    kayit = {
                        "tur": "Salsa20-128",
                        "ofset": bulunan_ofset,
                        "anahtar_hex": anahtar.hex(),
                        "anahtar_baytlar": anahtar,
                        "nonce_hex": nonce.hex(),
                        "sayac_hex": sayac.hex()
                    }
                    if not any(b["anahtar_hex"] == kayit["anahtar_hex"] for b in bulunanlar):
                        bulunanlar.append(kayit)

        ofset = bulunan_ofset + 1

    return bulunanlar


def tea_delta_ve_anahtar_ara(ham_veri: bytes) -> List[Dict[str, Any]]:
    # tea delta sabiti üzerinden bellekten anahtar çıkarır.
    bulunanlar: List[Dict[str, Any]] = []
    toplam = len(ham_veri)
    if toplam < 32:
        return bulunanlar

    # little-endian ve big-endian delta değerleri.
    delta_desenleri = [b"\xb9\x79\x37\x9e", b"\x9e\x37\x79\xb9"]

    for delta in delta_desenleri:
        ofset = 0
        while True:
            bulunan_ofset = ham_veri.find(delta, ofset)
            if bulunan_ofset == -1:
                break

            # delta çevresindeki 128-bit anahtar adaylarını inceler.
            baslangic = max(0, bulunan_ofset - 128)
            bitis = min(toplam - 16, bulunan_ofset + 128)

            for aday_ofset in range(baslangic, bitis, 4):
                if aday_ofset == bulunan_ofset:
                    continue
                aday_blok = ham_veri[aday_ofset:aday_ofset + 16]
                if len(aday_blok) == 16 and len(set(aday_blok)) >= 10:
                    ent = shannon_entropisi_hesapla(aday_blok)
                    if ent >= 3.2:
                        kayit = {
                            "tur": "TEA-XTEA-128",
                            "delta_ofset": bulunan_ofset,
                            "anahtar_ofset": aday_ofset,
                            "anahtar_hex": aday_blok.hex(),
                            "anahtar_baytlar": aday_blok
                        }
                        if not any(b["anahtar_hex"] == kayit["anahtar_hex"] for b in bulunanlar):
                            bulunanlar.append(kayit)
                            if len(bulunanlar) >= 20:
                                return bulunanlar

            ofset = bulunan_ofset + 1

    return bulunanlar


def rc4_sbox_ara(ham_veri: bytes) -> List[Dict[str, Any]]:
    # bellekten rc4 s-box permütasyon dizisini arar.
    bulunanlar: List[Dict[str, Any]] = []
    toplam = len(ham_veri)
    if toplam < 256:
        return bulunanlar

    tam_kume = set(range(256))
    adim = 16 if toplam > 100000 else 4

    for ofset in range(0, min(toplam - 256, 500000), adim):
        blok = ham_veri[ofset:ofset + 256]
        if set(blok) == tam_kume:
            kayit = {
                "tur": "RC4-SBox-Permutasyonu",
                "ofset": ofset,
                "onizleme_hex": blok[:32].hex()
            }
            if not any(b["ofset"] == ofset for b in bulunanlar):
                bulunanlar.append(kayit)
                if len(bulunanlar) >= 10:
                    break

    return bulunanlar


def der_rsa_anahtari_ara(ham_veri: bytes) -> List[str]:
    # der formatındaki rsa anahtarını pem formatına dönüştürür.
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend

    bulunan_pemler: List[str] = []
    toplam = len(ham_veri)

    # pkcs#1 ve pkcs#8 başlangıç baytları kontrolü.
    for eslesme in re.finditer(rb"\x30\x82([\x01-\x08][\x00-\xff])\x02\x01\x00", ham_veri):
        baslangic = eslesme.start()
        uzunluk_baytlari = eslesme.group(1)
        govde_uzunlugu = int.from_bytes(uzunluk_baytlari, "big")
        toplam_uzunluk = govde_uzunlugu + 4

        if baslangic + toplam_uzunluk <= toplam:
            aday_der = ham_veri[baslangic:baslangic + toplam_uzunluk]
            try:
                anahtar = serialization.load_der_private_key(aday_der, password=None, backend=default_backend())
                pem_veri = anahtar.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode("utf-8", errors="ignore")
                if pem_veri not in bulunan_pemler:
                    bulunan_pemler.append(pem_veri)
            except Exception:
                continue

    return bulunan_pemler


def bellekten_anahtar_ara(
    ham_veri: bytes,
    maksimum_aday: int = 50
) -> Dict[str, Any]:
    # bellek dökümünden simetrik ve asimetrik anahtarları çıkarır.
    bulunan_rsa_anahtarlari: List[str] = []
    bulunan_genisletilmis_aes128: List[str] = []
    bulunan_genisletilmis_aes256: List[str] = []
    yuksek_entropili_aes_adaylari: Set[str] = set()
    aday_128bit: Set[str] = set()
    aday_192bit: Set[str] = set()
    aday_256bit: Set[str] = set()

    # 1. rsa pem özel anahtarlarını arar.
    for eslesme in re.finditer(PEM_RSA_DESENI, ham_veri):
        pem_metin = eslesme.group(0).decode("utf-8", errors="ignore")
        if pem_metin not in bulunan_rsa_anahtarlari:
            bulunan_rsa_anahtarlari.append(pem_metin)

    # 2. der formatlı rsa anahtarlarını arar.
    der_rsa_listesi = der_rsa_anahtari_ara(ham_veri)
    for der_pem in der_rsa_listesi:
        if der_pem not in bulunan_rsa_anahtarlari:
            bulunan_rsa_anahtarlari.append(der_pem)

    # 3. chacha20 durum matrisi anahtarlarını arar.
    bulunan_chacha = chacha20_matris_ara(ham_veri)

    # 4. salsa20 durum matrisi anahtarlarını arar.
    bulunan_salsa = salsa20_matris_ara(ham_veri)

    # 5. tea delta anahtarlarını arar.
    bulunan_tea = tea_delta_ve_anahtar_ara(ham_veri)

    # 6. rc4 s-box permütasyonlarını arar.
    bulunan_rc4 = rc4_sbox_ara(ham_veri)

    toplam_boyut = len(ham_veri)
    adim = 4  # 4 baytlık bellek hizalama kontrolü.

    # 7. genişletilmiş aes-256 çizelgesini arar.
    if toplam_boyut >= 240:
        for ofset in range(0, min(toplam_boyut - 240, 2000000), adim):
            blok = ham_veri[ofset:ofset + 240]
            if aes256_anahtar_genisletmesi_dogrula(blok):
                ana_anahtar_hex = blok[:32].hex()
                if ana_anahtar_hex not in bulunan_genisletilmis_aes256:
                    bulunan_genisletilmis_aes256.append(ana_anahtar_hex)

    # 8. genişletilmiş aes-128 çizelgesini arar.
    if toplam_boyut >= 176:
        for ofset in range(0, min(toplam_boyut - 176, 2000000), adim):
            blok = ham_veri[ofset:ofset + 176]
            if aes128_anahtar_genisletmesi_dogrula(blok):
                ana_anahtar_hex = blok[:16].hex()
                if ana_anahtar_hex not in bulunan_genisletilmis_aes128:
                    bulunan_genisletilmis_aes128.append(ana_anahtar_hex)

    # 9. yüksek entropili evrensel anahtar adaylarını inceler.
    sinir = min(toplam_boyut - 32, 1000000)
    if sinir > 0:
        for ofset in range(0, sinir, 16):
            aday_16 = ham_veri[ofset:ofset + 16]
            if len(aday_16) == 16 and len(set(aday_16)) >= 13:
                ent_16 = shannon_entropisi_hesapla(aday_16)
                if ent_16 >= 3.80:
                    hex16 = aday_16.hex()
                    yuksek_entropili_aes_adaylari.add(hex16)
                    aday_128bit.add(hex16)

            # 24 baytlık anahtar adayları.
            if ofset + 24 <= toplam_boyut:
                aday_24 = ham_veri[ofset:ofset + 24]
                if len(set(aday_24)) >= 19 and shannon_entropisi_hesapla(aday_24) >= 4.2:
                    aday_192bit.add(aday_24.hex())

            # 32 baytlık anahtar adayları.
            aday_32 = ham_veri[ofset:ofset + 32]
            if len(aday_32) == 32 and len(set(aday_32)) >= 25:
                if shannon_entropisi_hesapla(aday_32) >= 4.6:
                    aday_256bit.add(aday_32.hex())

            if len(yuksek_entropili_aes_adaylari) >= maksimum_aday and len(aday_256bit) >= maksimum_aday:
                break

    # curve25519 ve x25519 anahtar çifti taraması.
    bulunan_x25519 = curve25519_anahtar_ara(ham_veri)

    return {
        "rsa_anahtar_sayisi": len(bulunan_rsa_anahtarlari),
        "rsa_anahtarlari": bulunan_rsa_anahtarlari,
        "dogrulanmis_aes128_anahtarlari": bulunan_genisletilmis_aes128,
        "dogrulanmis_aes256_anahtarlari": bulunan_genisletilmis_aes256,
        "chacha20_anahtarlari": bulunan_chacha,
        "salsa20_anahtarlari": bulunan_salsa,
        "tea_anahtarlari": bulunan_tea,
        "x25519_anahtarlari": bulunan_x25519,
        "rc4_sbox_sayisi": len(bulunan_rc4),
        "rc4_durumlari": bulunan_rc4,
        "olasi_aes_anahtar_adaylari": list(yuksek_entropili_aes_adaylari)[:maksimum_aday],
        "olasi_128bit_adaylari": list(aday_128bit)[:maksimum_aday],
        "olasi_192bit_adaylari": list(aday_192bit)[:maksimum_aday],
        "olasi_256bit_adaylari": list(aday_256bit)[:maksimum_aday]
    }


def curve25519_anahtar_ara(ham_veri: bytes) -> List[Dict[str, Any]]:
    """
    bellek icerisinde curve25519 (x25519 / ed25519) ozel anahtarlarini
    rfc 7748 clamping kurali ve libsodium/openssl anahtar cifti yapilariyla arar.
    """
    bulunanlar: List[Dict[str, Any]] = []
    toplam = len(ham_veri)
    if toplam < 32:
        return bulunanlar

    from cryptography.hazmat.primitives.asymmetric import x25519

    # 32 bayt aralıklarla anahtarları tarar.
    for i in range(0, toplam - 32, 16):
        aday_ozel = ham_veri[i:i + 32]
        # rfc 7748 skaler bit kontrolü.
        if (aday_ozel[0] & 0x07 == 0) and ((aday_ozel[31] & 0xC0) == 0x40):
            # sıfır bayt dolgu kontrolü.
            if aday_ozel.count(0) <= 3 and len(set(aday_ozel)) >= 18:
                try:
                    priv = x25519.X25519PrivateKey.from_private_bytes(aday_ozel)
                    pub_bytes = priv.public_key().public_bytes_raw()
                    
                    # açık anahtar çifti kontrolü.
                    yanindaki = ham_veri[i + 32:i + 64] if i + 64 <= toplam else b""
                    eslesme = (yanindaki == pub_bytes)

                    kayit = {
                        "tur": "Curve25519",
                        "ofset": i,
                        "ozel_anahtar_hex": aday_ozel.hex(),
                        "kamu_anahtar_hex": pub_bytes.hex(),
                        "libsodium_cifti_mi": eslesme
                    }
                    if not any(k["ozel_anahtar_hex"] == kayit["ozel_anahtar_hex"] for k in bulunanlar):
                        bulunanlar.append(kayit)
                        if len(bulunanlar) >= 10:
                            break
                except Exception:
                    continue

    bulunanlar.sort(key=lambda x: x["libsodium_cifti_mi"], reverse=True)
    return bulunanlar


def rsa_asal_carpan_rekonstruksiyon(p: int, q: int, e: int = 65537) -> Optional[str]:
    """
    bellekten çıkarılan p ve q asal çarpanlarını kullanarak tam rsa özel anahtarını (pem) inşa eder.
    (wannacry / wanakiwi tarzı bellek kurtarma rekonstrüksiyonu)
    """
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization

        n = p * q
        phi = (p - 1) * (q - 1)
        d = pow(e, -1, phi)
        dmp1 = d % (p - 1)
        dmq1 = d % (q - 1)
        iqmp = pow(q, -1, p)

        public_numbers = rsa.RSAPublicNumbers(e, n)
        private_numbers = rsa.RSAPrivateNumbers(
            p=p,
            q=q,
            d=d,
            dmp1=dmp1,
            dmq1=dmq1,
            iqmp=iqmp,
            public_numbers=public_numbers
        )

        private_key = private_numbers.private_key()
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        return pem.decode("utf-8")
    except Exception:
        return None


def zayif_prng_tohum_tara(
    hedef_sifreli: bytes,
    referans_duz_metin: bytes,
    merkez_zaman: int,
    aralik_saniye: int = 3600
) -> Optional[Dict[str, Any]]:
    """
    zaman damgası tabanlı zayıf prng (c srand(time) / rand() veya python random) kullanan
    fidye yazılımları için zaman aralığında tohum taraması (seed bruteforce) yapar.
    """
    if len(hedef_sifreli) < len(referans_duz_metin) or not referans_duz_metin:
        return None

    hedef_baslik = hedef_sifreli[:len(referans_duz_metin)]
    baslangic = merkez_zaman - aralik_saniye
    bitis = merkez_zaman + aralik_saniye

    # 1. c doğrusal eşlik üreteci (lcg) simülasyonu.
    for tohum in range(baslangic, bitis + 1):
        # msvc rand simülasyonu.
        durum = tohum & 0xFFFFFFFF
        uretilen_baytlar = bytearray()
        for _ in range(len(hedef_baslik)):
            durum = (durum * 214013 + 2531011) & 0xFFFFFFFF
            uretilen_baytlar.append((durum >> 16) & 0xFF)

        # xor testi.
        cozum = bytes(hedef_baslik[i] ^ uretilen_baytlar[i] for i in range(len(hedef_baslik)))
        if cozum == referans_duz_metin:
            return {
                "basarili": True,
                "tip": "C-MSVC-PRNG",
                "tohum": tohum,
                "turetilen_anahtar_hex": bytes(uretilen_baytlar[:32]).hex()
            }

    return None


def bellek_dosyasini_tara(dosya_yolu: str, maksimum_boyut_mb: int = 512) -> Dict[str, Any]:
    """
    belirtilen bellek dökümünü (ram dump) veya dosyasını açıp derin anahtar taraması yapar.
    maksimum boyut parametresi ile bellek aşımını (oom) önler.
    """
    if not os.path.exists(dosya_yolu):
        return {"hata": "Dosya bulunamadı"}

    try:
        dosya_boyutu = os.path.getsize(dosya_yolu)
        if dosya_boyutu == 0:
            return {"hata": "Dosya boş"}

        with open(dosya_yolu, "rb") as dosya_nesnesi:
            okunan_veri = dosya_nesnesi.read(min(dosya_boyutu, maksimum_boyut_mb * 1024 * 1024))
            return bellekten_anahtar_ara(okunan_veri)
    except Exception as hata_mesaji:
        return {"hata": str(hata_mesaji)}
