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


class SysFreeString(angr.SimProcedure):
    def run(self, bstrString):
        # if bstrString.symbolic:
        #     return self.state.solver.BVS(
        #         "retval_{}".format(self.display_name), self.arch.bits
        #     )
        self.state.heap.free(self.state.solver.eval(bstrString))
