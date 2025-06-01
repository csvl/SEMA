import os
import sys
import logging
import angr

import os

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ.get("LOG_LEVEL", "INFO"))
except Exception as e:
    print(e)


class HeapFree(angr.SimProcedure):
    def run(self, hHeap, dwFlags, lpMem):
        lw.debug("HeapFree.run")
        try:
            self.state.heap.free(lpMem)
            return self.state.solver.BVV(1, self.arch.bits)
        except:
            return self.state.solver.BVV(0, self.arch.bits)
