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


class InternetSetOptionW(angr.SimProcedure):
    def run(self, arg1, arg2, arg3, arg4):
        return self.state.solver.BVS(
            "retval_{}".format(self.display_name), self.arch.bits
        )
