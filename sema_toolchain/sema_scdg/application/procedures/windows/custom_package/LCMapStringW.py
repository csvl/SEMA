import os
import sys


import logging
import sys
import angr

import os

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)

class LCMapStringW(angr.SimProcedure):
    def run(self, Locale, dwMapFlags, lpSrcStr, cchSrc, lpDestStr, cchDest):
        return cchSrc
