import logging
import angr

import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class HttpQueryInfoW(angr.SimProcedure):
    def run(self, arg1, arg2, arg3, arg4, arg5):
        return self.state.solver.BVS(
            "retval_{}".format(self.display_name), self.arch.bits
        )
