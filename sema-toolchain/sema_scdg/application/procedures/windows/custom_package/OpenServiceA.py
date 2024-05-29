import logging
import angr

import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class OpenServiceA(angr.SimProcedure):
    def run(self, hSCManager, lpServiceName, dwDesiredAccess):
        retval = self.state.solver.BVS(
            "retval_{}".format(self.display_name), self.arch.bits
        )
        self.state.solver.add(retval != 0)
        return retval
