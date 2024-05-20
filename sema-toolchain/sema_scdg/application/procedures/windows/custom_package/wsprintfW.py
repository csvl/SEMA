import logging
import angr

import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class wsprintfW(angr.SimProcedure):
    def run(self, arg1, arg2):
        return self.state.solver.BVS(
            "retval_{}".format(self.display_name), self.arch.bits
        )
