import os
import struct
import io
import base64
import hashlib
import zipfile
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Tuple, Any
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from rescat.cozuculer.temel_cozucu import TemelCozucu
from rescat.cekirdek.dosya_tanimlayici import format_icerik_dogrula


class OfficeCozucu(TemelCozucu):
    """
    parolalı veya şifreli microsoft office belgelerini (agile / standard encryption)
    çözen ve orijinal .xlsx, .docx, .pptx arşivini çıkaran yerel çözücü modülü.
    """

    def __init__(
        self,
        parolalar: Optional[List[str]] = None,
        kuru_calistirma: bool = False,
        yedek_al: bool = True,
        hedef_cikti_dizini: Optional[str] = None
    ) -> None:
        super().__init__(
            kuru_calistirma=kuru_calistirma,
            yedek_al=yedek_al,
            hedef_cikti_dizini=hedef_cikti_dizini
        )
        self.parolalar: List[str] = parolalar or [
            "VelvetSweatshop",
            "",
            "123456",
            "password",
            "1234",
            "admin",
            "12345678",
            "root",
            "excel",
            "test"
        ]

    @staticmethod
    def office_belgesi_mi(ham_veri: bytes) -> bool:
        if len(ham_veri) < 512 or ham_veri[:8] != b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
            return False
        return (
            b"EncryptedPackage" in ham_veri
            or b"E\x00n\x00c\x00r\x00y\x00p\x00t\x00e\x00d\x00P\x00a\x00c\x00k\x00a\x00g\x00e" in ham_veri
        )

    @staticmethod
    def _ole_akislari_ayristir(ham_veri: bytes) -> Dict[str, bytes]:
        if len(ham_veri) < 512 or ham_veri[:8] != b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
            return {}

        sector_size = 1 << struct.unpack("<H", ham_veri[30:32])[0]
        num_fat_sectors = struct.unpack("<I", ham_veri[44:48])[0]
        dir_start_sector = struct.unpack("<I", ham_veri[48:52])[0]
        fat_sectors = [struct.unpack("<I", ham_veri[76 + i*4:80 + i*4])[0] for i in range(min(num_fat_sectors, 109))]
        
        fat = []
        for s_id in fat_sectors:
            if s_id >= 0xFFFFFFFD:
                continue
            offset = (s_id + 1) * sector_size
            s_data = ham_veri[offset:offset + sector_size]
            for i in range(0, len(s_data), 4):
                fat.append(struct.unpack("<I", s_data[i:i+4])[0])

        dir_data = bytearray()
        curr_s = dir_start_sector
        while curr_s < 0xFFFFFFFD and curr_s < len(fat):
            offset = (curr_s + 1) * sector_size
            dir_data.extend(ham_veri[offset:offset + sector_size])
            curr_s = fat[curr_s]

        streams = {}
        for i in range(0, len(dir_data), 128):
            entry = dir_data[i:i+128]
            if len(entry) < 128:
                break
            name_len = struct.unpack("<H", entry[64:66])[0]
            if name_len == 0:
                continue
            raw_name = entry[:name_len].decode("utf-16le", errors="ignore").rstrip("\x00")
            entry_type = entry[66]
            start_s = struct.unpack("<I", entry[116:120])[0]
            size = struct.unpack("<Q", entry[120:128])[0]
            if entry_type == 2:
                s_bytes = bytearray()
                curr = start_s
                while curr < 0xFFFFFFFD and curr < len(fat) and len(s_bytes) < size:
                    off = (curr + 1) * sector_size
                    s_bytes.extend(ham_veri[off:off + sector_size])
                    curr = fat[curr]
                streams[raw_name] = bytes(s_bytes[:size])

        return streams

    def baytlari_coz(self, sifreli_veri: bytes) -> Optional[bytes]:
        if not self.office_belgesi_mi(sifreli_veri):
            return None

        # encryptioninfo xml içeriğini ayıklar.
        s_xml = sifreli_veri.find(b"<?xml")
        if s_xml == -1:
            return None
        e_xml = sifreli_veri.find(b"</encryption>", s_xml)
        if e_xml == -1:
            return None
        e_xml += len(b"</encryption>")
        
        try:
            xml_bytes = sifreli_veri[s_xml:e_xml]
            root = ET.fromstring(xml_bytes)
        except Exception:
            return None

        ns = {
            "e": "http://schemas.microsoft.com/office/2006/encryption",
            "p": "http://schemas.microsoft.com/office/2006/keyEncryptor/password"
        }

        key_data_el = root.find("e:keyData", ns)
        key_encryptor_el = root.find(".//p:encryptedKey", ns)
        if key_data_el is None or key_encryptor_el is None:
            return None

        try:
            salt = base64.b64decode(key_encryptor_el.get("saltValue", ""))
            spin_count = int(key_encryptor_el.get("spinCount", "100000"))
            enc_verifier_input = base64.b64decode(key_encryptor_el.get("encryptedVerifierHashInput", ""))
            enc_verifier_val = base64.b64decode(key_encryptor_el.get("encryptedVerifierHashValue", ""))
            enc_key_val = base64.b64decode(key_encryptor_el.get("encryptedKeyValue", ""))
            pkg_salt = base64.b64decode(key_data_el.get("saltValue", ""))
        except Exception:
            return None

        block_key_input = bytes.fromhex("fea7d2763b4b9e79")
        block_key_val = bytes.fromhex("d7aa0f6d3061344e")
        block_key_secret = bytes.fromhex("146e0be7abacd0d6")

        streams = self._ole_akislari_ayristir(sifreli_veri)
        enc_pkg = streams.get("EncryptedPackage")
        if not enc_pkg or len(enc_pkg) < 16:
            return None

        unenc_size = struct.unpack("<Q", enc_pkg[:8])[0]
        enc_data = enc_pkg[8:]

        for pwd in self.parolalar:
            try:
                pwd_bytes = pwd.encode("utf-16le")
                h = hashlib.sha512(salt + pwd_bytes).digest()
                for i in range(spin_count):
                    h = hashlib.sha512(i.to_bytes(4, "little") + h).digest()

                h_input = hashlib.sha512(h + block_key_input).digest()[:32]
                cipher_v = Cipher(algorithms.AES(h_input), modes.CBC(salt), backend=default_backend()).decryptor()
                v_in = cipher_v.update(enc_verifier_input) + cipher_v.finalize()
                v_hash = hashlib.sha512(v_in).digest()

                h_val = hashlib.sha512(h + block_key_val).digest()[:32]
                cipher_val = Cipher(algorithms.AES(h_val), modes.CBC(salt), backend=default_backend()).decryptor()
                v_val = cipher_val.update(enc_verifier_val) + cipher_val.finalize()

                if v_hash == v_val[:len(v_hash)]:
                    # parola doğrulandı.
                    h_sec = hashlib.sha512(h + block_key_secret).digest()[:32]
                    cipher_sec = Cipher(algorithms.AES(h_sec), modes.CBC(salt), backend=default_backend()).decryptor()
                    pkg_key = (cipher_sec.update(enc_key_val) + cipher_sec.finalize())[:32]

                    # parçalı aes şifre çözümü.
                    dec_pkg = bytearray()
                    segment_size = 4096
                    for seg_idx in range(0, (len(enc_data) + segment_size - 1) // segment_size):
                        seg_bytes = enc_data[seg_idx * segment_size : (seg_idx + 1) * segment_size]
                        if not seg_bytes:
                            break
                        iv_hash = hashlib.sha512(pkg_salt + seg_idx.to_bytes(4, "little")).digest()[:16]
                        cipher_pkg = Cipher(algorithms.AES(pkg_key), modes.CBC(iv_hash), backend=default_backend()).decryptor()
                        dec_pkg.extend(cipher_pkg.update(seg_bytes) + cipher_pkg.finalize())

                    final_data = bytes(dec_pkg[:unenc_size])
                    gecerli, _ = format_icerik_dogrula(final_data)
                    if gecerli:
                        return final_data
            except Exception:
                continue

        return None
