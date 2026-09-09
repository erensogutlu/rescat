# RESCAT - Ransomware Analysis and Decryption Toolkit

[English](README_EN.md) | [Türkçe](README.md)

```
  ██████╗ ███████╗███████╗ ██████╗ █████╗ ████████╗
  ██╔══██╗██╔════╝██╔════╝██╔════╝██╔══██╗╚══██╔══╝
  ██████╔╝█████╗  ███████╗██║     ███████║   ██║   
  ██╔══██╗██╔══╝  ╚════██║██║     ██╔══██║   ██║   
  ██║  ██║███████╗███████║╚██████╗██║  ██║   ██║   
  ╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   
```

A 100% offline (air-gapped) incident response (DFIR) and cryptanalysis tool designed for digital forensics, algorithm identification, in-memory key extraction, and decryption across modern ransomware strains (LockBit, Akira, BlackCat, Babuk, ESXiArgs, STOP/Djvu, etc.) and encrypted assets.

---

## Features

| Feature | Description |
|---|---|
| 100% Offline | Requires no network connectivity; operates fully air-gapped without leaking telemetry or keys. |
| Autonomous Decryption | Zero-parameter, single-command file type detection, algorithm identification, and recovery. |
| X25519 & Hybrid ECDH | Ephemeral public key extraction and shared secret computation for LockBit 3.0, Akira, and Babuk. |
| Sosemanuk Stream Cipher | eSTREAM Profile 1 stream cipher decryptor for ESXiArgs and Babuk virtual disks. |
| Intermittent Encryption | Carves unencrypted plaintext sectors from block-skipped encrypted files. |
| ESXi VMDK Reconstruction | Generates descriptor files for header-wiped -flat.vmdk virtual disks. |
| Live Process Freezer | Freezes running ransomware processes via SIGSTOP and dumps RAM. |
| Crib-Dragging | Keyless 100% plaintext recovery exploiting stream cipher nonce reuse vulnerabilities. |
| Multi-Core Cracker | High-performance multiprocessing dictionary and rule-based mutation engine. |
| 35+ Formats & Chi-Square | Validates structural integrity across database and proprietary binary formats. |
| Forensic Recovery (DFIR) | Recovers VSS shadow copies, Btrfs/ZFS snapshots, and SQLite WAL journal records. |
| RAM Key Hunter | Extracts AES-128/256, ChaCha20, Salsa20, and RSA keys from memory dumps. |

---

## Installation

```bash
git clone https://github.com/erensogutlu/rescat.git
cd rescat
pip install -r requirements.txt
pip install -e .
```

System Requirements: Python 3.8 or higher (Linux / Windows)

---

## Quick Start

### 1. Autonomous Directory Scan and Decryption
```bash
sudo rescat genel-tarama /target/case_directory/
```

### 2. Single File Recovery
```bash
sudo rescat ozel-tarama /target/document.pdf.locked
```

### 3. Live Process Freezing and Memory Dump
```bash
# Scan and list active suspicious processes:
sudo rescat canli-avci --tara

# Freeze specified process and dump RAM to disk:
sudo rescat canli-avci --pid <PID> --dokum /tmp/ram.dmp
```

### 4. Key Extraction from Memory Dump
```bash
rescat avci /tmp/ram.dmp
```

### 5. ESXi VMDK Reconstruction
```bash
sudo rescat vmdk-kurtar /datastore/server-flat.vmdk --cikti /recovery_directory/
```

### 6. Keyless Recovery via Nonce Reuse (Crib-Dragging)
```bash
rescat crib-drag file1.pdf.enc file2.png.enc
```

### 7. Forensic Recovery (Shadow Copies, Snapshots, SQLite WAL)
```bash
sudo rescat adli-kurtar /target/case_directory/
```

### 8. Interactive Terminal Guide
```bash
sudo python3 rescat.py
```

---

## Command Reference

| Command | Description |
|---|---|
| rescat genel-tarama [DIR] | Automated directory-wide scanning, analysis, and decryption |
| rescat ozel-tarama FILE | Deep analysis and recovery focused on a specific file |
| rescat analiz TARGET | Entropy mapping, statistical analysis, and algorithm signature profiling |
| rescat coz TARGET | Direct decryption with specific parameters (--algoritma, --anahtar) |
| rescat otonom TARGET | Fully autonomous triage and recovery requiring no external input |
| rescat canli-avci | Freeze active malware processes (SIGSTOP) and extract memory |
| rescat avci DUMP | Extract AES, X25519, ChaCha, Salsa, TEA, RC4, and RSA keys from RAM |
| rescat chacha-avci DUMP | Locate ChaCha20/Salsa20 state matrices and extract keys from memory |
| rescat vmdk-kurtar FILE | Reconstruct ESXi virtual disk descriptors and partition layout |
| rescat crib-drag F1 F2 | Keyless plaintext recovery of two files under nonce reuse |
| rescat aralikli FILE | Intermittent encryption analysis and plaintext sector carving |
| rescat adli-kurtar TARGET | Recover VSS, filesystem snapshots, SQLite WAL, and office temp files |
| rescat kpa --orijinal .. --sifreli .. | Known-Plaintext Attack (KPA) to recover XOR/keystream keys |
| rescat zaman-kirici FILE | Break time-seeded weak PRNG/LCG encryption keys |
| rescat zayif-rsa -n .. -e .. | Factorize weak RSA moduli using Fermat and Wiener attacks |
| rescat yapisal-kurtar FILE | Deep structural carving for partially encrypted ZIP, SQLite, PDF, MP4 |
| rescat keystream F1 F2 | Keystream extraction and plaintext replay attack |
| rescat onar FILE --format .. | Repair corrupted or wiped file headers using standard templates |
| rescat interaktif | Launch two-choice interactive terminal wizard (TUI) |

---

## Project Structure

```
rescat/
├── rescat.py                  # CLI main entry point
├── pyproject.toml             # Packaging and distribution configuration
├── requirements.txt           # Dependency specifications
├── README.md                  # Turkish documentation
├── README_EN.md               # English documentation
├── SECURITY.md                # Security vulnerability reporting policy
├── CONTRIBUTING.md            # Contribution guidelines
├── CHANGELOG.md               # Release notes and version history
├── .github/workflows/ci.yml   # GitHub Actions CI workflow
├── rescat/
│   ├── ana_komut.py           # CLI manager with 21 subcommands
│   ├── otonom.py              # Autonomous DFIR analysis and recovery engine
│   ├── analizciler/           # Memory inspection, live process, and DFIR modules
│   ├── cekirdek/              # Cryptographic analysis and cryptanalysis engines
│   ├── cozuculer/             # Decryption algorithm implementations
│   └── yardimcilar/           # TUI, console logging, and reporting components
```

---

## Legal Disclaimer

This tool is intended exclusively for authorized digital forensics investigations, DFIR incident response operations, and victims recovering their own data. Operating this tool on unauthorized systems is strictly illegal. The user assumes full legal responsibility for any misuse.

---

Developer: Eren Söğütlü
Version: 1.0.0
