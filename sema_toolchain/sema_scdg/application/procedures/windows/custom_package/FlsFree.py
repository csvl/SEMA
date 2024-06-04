import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
from .TlsFree import TlsFree
from .FlsSetValue import FlsSetValue


class FlsFree(TlsFree):
    KEY = "win32_fls"
    SETTER = FlsSetValue
