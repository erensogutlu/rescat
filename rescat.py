#!/usr/bin/env python3
import sys
import os

proje_kok_dizini = os.path.dirname(os.path.abspath(__file__))
if proje_kok_dizini not in sys.path:
    sys.path.insert(0, proje_kok_dizini)

from rescat.ana_komut import ana_calistirici

if __name__ == "__main__":
    ana_calistirici()
