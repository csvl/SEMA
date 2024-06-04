import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
from .TlsSetValue import TlsSetValue


class FlsSetValue(TlsSetValue):
    KEY = "win32_fls"
