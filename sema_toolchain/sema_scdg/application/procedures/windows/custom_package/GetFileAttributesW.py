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


class GetFileAttributesW(angr.SimProcedure):
    def run(self, lpFileName):
        try:
            lw.debug(self.state.mem[lpFileName].string.concrete)
            if lpFileName == "" :
                return 0
        except:
            lw.debug(self.state.memory.load(lpFileName, 0x20))
        retval = self.state.solver.BVS(
            "retval_{}".format(self.display_name), self.arch.bits
        )
        return retval
