# Contributing to rescat

We welcome contributions from the digital forensics, incident response (DFIR), and applied cryptography communities!

## How to Contribute

1. **Fork the Repository**:
   Click the Fork button at the top right of the GitHub repository.

2. **Clone and Setup Virtual Environment**:
   ```bash
   git clone https://github.com/erensogutlu/rescat.git
   cd rescat
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   pip install -e .
   ```

3. **Create a Feature Branch**:
   ```bash
   git checkout -b feature/new-cipher-support
   ```

4. **Verify Implementation**:
   Before submitting, ensure the package builds and CLI executes properly:
   ```bash
   python3 -m rescat.ana_komut --help
   ```

5. **Implement Your Changes**:
   - Write clean, well-commented Python code following PEP 8.
   - Ensure the code works in an air-gapped environment (no mandatory outbound internet dependencies).

6. **Verify and Commit**:
   ```bash
   python3 -m rescat.ana_komut --help
   git commit -m "feat(ciphers): add support for new ransomware variant"
   ```

7. **Submit a Pull Request**:
   Open a PR against the `main` branch with a clear description of the cryptographic implementation, test cases, and rationale.

## Areas for Contribution
- New ransomware format parsers and offline keys.
- Hardware-accelerated (C-extension / OpenCL) key bruteforcers.
- Linux filesystem snapshot connectors.
- Document and database structural carvers.
