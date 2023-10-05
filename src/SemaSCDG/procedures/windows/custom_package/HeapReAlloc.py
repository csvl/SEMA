import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class HeapReAlloc(angr.SimProcedure):
    def run(self, hHeap, dwFlags, lpMem, dwBytes):
        # Update heap size
        self.state.globals["HeapSize"][self.state.solver.eval(lpMem)] = dwBytes
        return self.state.heap._realloc(lpMem, dwBytes)
