import os
import sys


from .TlsGetValue import TlsGetValue


class FlsGetValue(TlsGetValue):
    KEY = "win32_fls"
