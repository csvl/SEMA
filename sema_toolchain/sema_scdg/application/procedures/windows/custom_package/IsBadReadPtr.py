import os
import sys
import logging
import angr

import os

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ.get("LOG_LEVEL", "INFO"))
except Exception as e:
    print(e)


class IsBadReadPtr(angr.SimProcedure):
    def run(self, lp, ucb):
        lw.debug("IsBadReadPtr.run")
        size = self.state.solver.eval(ucb)
        try:
            garbage = self.state.memory.load(lp, size)
            return 0
        except Exception:
            return 1