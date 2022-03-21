import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class HeapReAlloc(angr.SimProcedure):
    def run(self, hHeap, dwFlags, lpMem, dwBytes):
        return self.state.heap._realloc(lpMem, dwBytes)
