import logging
import angr

import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class HeapReAlloc(angr.SimProcedure):
    def run(self, hHeap, dwFlags, lpMem, dwBytes):
        self.state.globals["HeapSize"][self.state.solver.eval(lpMem)] = dwBytes
        return self.state.heap._realloc(lpMem, dwBytes)
