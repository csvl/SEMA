import os
import sys
import logging
import angr

import os

import claripy

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ.get("LOG_LEVEL", "INFO"))
except Exception as e:
    print(e)


class SetCurrentDirectoryW(angr.SimProcedure):
    def run(self, lpPathName):
        try:
            lw.debug(self.state.mem[lpPathName].string.concrete)
            if lpPathName == "" :
                return 0
        except:
            lw.debug("SetCurrentDirectoryA with non concrete path")

        retval = self.state.solver.BVS(
            "retval_{}".format(self.display_name), self.arch.bits
        )
        self.state.solver.add(claripy.Or(retval == 0, retval == 1))
        return retval
