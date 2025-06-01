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


class OpenMutexA(angr.SimProcedure):
    def run(self, dwDesiredAccess, bInheritHandle, lpName):
        lw.debug("OpenMutexA.run")
        try:
            name = self.state.mem[lpName].string.concrete.decode("ascii")
            lw.debug("mutex name: %s", name)
        except:
            pass

        retval = self.state.solver.BVS(
            "retval_{}".format(self.display_name), self.arch.bits
        )
        return retval