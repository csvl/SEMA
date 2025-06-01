


import os
import sys


import angr


class GlobalFree(angr.SimProcedure):
    def run(self, addr):
        try:
            self.state.heap.free(addr)
            return self.state.solver.BVV(1, self.arch.bits)
        except:
            return self.state.solver.BVV(0, self.arch.bits)
