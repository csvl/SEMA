import os
import sys


import logging
import angr

import os

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)


class HeapReAlloc(angr.SimProcedure):
    def run(self, hHeap, dwFlags, lpMem, dwBytes):
        self.state.globals["HeapSize"][self.state.solver.eval(lpMem)] = dwBytes
        return self.state.heap._realloc(lpMem, dwBytes)
