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


class send(angr.SimProcedure):
    def run(self, s, buf, length, flags):
        if length.symbolic:
            return self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
        else:
            length = self.state.solver.eval(length)
            return length
