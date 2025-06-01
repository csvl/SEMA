import os
import sys


import angr

######################################
# free
######################################
class free(angr.SimProcedure):
    # pylint:disable=arguments-differ,unused-argument

    def run(self, ptr):
        try:
            self.state.heap.free(ptr)
            return self.state.solver.BVV(1, self.arch.bits)
        except:
            return self.state.solver.BVV(0, self.arch.bits)
