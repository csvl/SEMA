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


class Sleep(angr.SimProcedure):
    def run(self, time):
        lw.debug("Simulating Sleep for %s milliseconds" % self.state.solver.eval(time))
        return
