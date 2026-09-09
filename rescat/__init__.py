import warnings
from cryptography.utils import CryptographyDeprecationWarning

# eski blok şifreleyici uyarılarını filtreler.
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

# rescat paketi.
__version__ = "1.0.0"
__author__ = "rescat"
__description__ = "Ransomware Acil Durum Analiz ve Decryptor Paketi"
