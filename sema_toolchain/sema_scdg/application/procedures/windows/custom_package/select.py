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


class select(angr.SimProcedure):
    def run(self, nfds, readfds, writefds, exceptfds, timeout):
        retval = self.state.solver.BVS(
            "retval_{}".format(self.display_name), self.arch.bits
        )
        self.state.solver.add(self.state.solver.SGT(retval,0))
        return retval
