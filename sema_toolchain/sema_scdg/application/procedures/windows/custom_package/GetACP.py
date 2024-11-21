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


class GetACP(angr.SimProcedure):
    def run(self):
         ret_expr = self.state.solver.BVV(1252,  self.arch.bits)
         return ret_expr
