from .TlsFree import TlsFree
from .FlsSetValue import FlsSetValue


class FlsFree(TlsFree):
    KEY = "win32_fls"
    SETTER = FlsSetValue
