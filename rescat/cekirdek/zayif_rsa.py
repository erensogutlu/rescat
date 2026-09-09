import math
from typing import List, Optional, Tuple
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


def tam_kare_mi(sayi: int) -> Tuple[bool, int]:
    # tam kare kontrolü ve karekök hesabı.
    if sayi < 0:
        return False, 0
    kok = math.isqrt(sayi)
    return (kok * kok == sayi), kok


def fermat_carpanlara_ayir(modulus_n: int, maksimum_adim: int = 1000000) -> Optional[Tuple[int, int]]:
    # yakın çarpanları fermat yöntemiyle ayırır.
    if modulus_n % 2 == 0:
        return 2, modulus_n // 2

    a_degeri = math.isqrt(modulus_n)
    if a_degeri * a_degeri < modulus_n:
        a_degeri += 1

    for adim in range(maksimum_adim):
        b_kare = a_degeri * a_degeri - modulus_n
        kare_mi, b_degeri = tam_kare_mi(b_kare)
        if kare_mi:
            carpan_p = a_degeri - b_degeri
            carpan_q = a_degeri + b_degeri
            if carpan_p * carpan_q == modulus_n and carpan_p > 1 and carpan_q > 1:
                return carpan_p, carpan_q
        a_degeri += 1

    return None


def surekli_kesir_katsayilari(pay: int, payda: int) -> List[int]:
    # sürekli kesir açılımını hesaplar.
    katsayilar: List[int] = []
    while payda != 0:
        bolum = pay // payda
        katsayilar.append(bolum)
        pay, payda = payda, pay - bolum * payda
    return katsayilar


def yakinsek_degerler(katsayilar: List[int]) -> List[Tuple[int, int]]:
    # yakınsak kesir çiftlerini üretir.
    yakinsaklar: List[Tuple[int, int]] = []
    pay_onceki, pay_suanki = 0, 1
    payda_onceki, payda_suanki = 1, 0

    for katsayi in katsayilar:
        yeni_pay = katsayi * pay_suanki + pay_onceki
        yeni_payda = katsayi * payda_suanki + payda_onceki
        yakinsaklar.append((yeni_pay, yeni_payda))
        pay_onceki, pay_suanki = pay_suanki, yeni_pay
        payda_onceki, payda_suanki = payda_suanki, yeni_payda

    return yakinsaklar


def wiener_saldirisi(genel_us_e: int, modulus_n: int) -> Optional[Tuple[int, int, int]]:
    # wiener algoritmasıyla rsa anahtarını kurtarır.
    katsayilar = surekli_kesir_katsayilari(genel_us_e, modulus_n)
    yakinsaklar = yakinsek_degerler(katsayilar)

    for k_degeri, d_degeri in yakinsaklar:
        if k_degeri == 0 or d_degeri == 0:
            continue

        # ed - 1 denklemi kontrolü.
        pay = genel_us_e * d_degeri - 1
        if pay % k_degeri != 0:
            continue

        phi_n = pay // k_degeri

        # ikinci derece denklem kök hesabı.
        s_degeri = modulus_n - phi_n + 1
        diskriminant = s_degeri * s_degeri - 4 * modulus_n

        kare_mi, kok_disk = tam_kare_mi(diskriminant)
        if kare_mi and (s_degeri + kok_disk) % 2 == 0:
            carpan_p = (s_degeri + kok_disk) // 2
            carpan_q = (s_degeri - kok_disk) // 2

            if carpan_p * carpan_q == modulus_n and carpan_p > 1 and carpan_q > 1:
                return d_degeri, carpan_p, carpan_q

    return None


def rsa_ozel_anahtar_pem_olustur(carpan_p: int, carpan_q: int, genel_us_e: int = 65537) -> bytes:
    # p ve q çarpanlarıyla pem formatında özel anahtar oluşturur.
    modulus_n = carpan_p * carpan_q
    phi_n = (carpan_p - 1) * (carpan_q - 1)
    ozel_us_d = pow(genel_us_e, -1, phi_n)
    dmp1 = ozel_us_d % (carpan_p - 1)
    dmq1 = ozel_us_d % (carpan_q - 1)
    iqmp = pow(carpan_q, -1, carpan_p)

    anahtar_sayilari = rsa.RSAPrivateNumbers(
        p=carpan_p,
        q=carpan_q,
        d=ozel_us_d,
        dmp1=dmp1,
        dmq1=dmq1,
        iqmp=iqmp,
        public_numbers=rsa.RSAPublicNumbers(e=genel_us_e, n=modulus_n)
    )

    ozel_anahtar_nesnesi = anahtar_sayilari.private_key(backend=default_backend())
    return ozel_anahtar_nesnesi.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
