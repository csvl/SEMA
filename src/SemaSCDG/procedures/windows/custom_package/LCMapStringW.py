import logging
import sys
import angr

lw = logging.getLogger("CustomSimProcedureWindows")

class LCMapStringW(angr.SimProcedure):
    def run(self, Locale, dwMapFlags, lpSrcStr, cchSrc, lpDestStr, cchDest):
        return cchSrc
