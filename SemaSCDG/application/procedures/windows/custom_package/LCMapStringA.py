import logging
import sys
import angr

import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])

class LCMapStringA(angr.SimProcedure):
    def run(self, Locale, dwMapFlags, lpSrcStr, cchSrc, lpDestStr, cchDest):
        return cchSrc
