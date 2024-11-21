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


class RegisterClassExA(angr.SimProcedure):

    def run(
        self,
        unnamedParam1
    ):
        return self.state.solver.BVS("retval_{}".format(self.display_name),  self.arch.bits)
