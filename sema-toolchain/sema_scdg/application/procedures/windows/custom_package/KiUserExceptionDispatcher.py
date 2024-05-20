import logging
import angr

import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class KiUserExceptionDispatcher(angr.SimProcedure):
    def run(self, pExceptionRec, Pcontext):
        return self.state.solver.BVS(
            "retval_{}".format(self.display_name), self.arch.bits
        )
