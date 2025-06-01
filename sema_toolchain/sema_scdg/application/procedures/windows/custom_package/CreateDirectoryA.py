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


class CreateDirectoryA(angr.SimProcedure):
    def run(self, lpPathName, lpSecurityAttributes):
        lw.debug("enter CreateDirectoryA")
        try:
            lw.debug("path: %s", self.state.mem[lpPathName].string.concrete.decode("ascii"))
        except:
            lw.debug("path is not concrete")

        return 1