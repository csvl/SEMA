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


class CreateDirectoryW(angr.SimProcedure):
    def run(self, lpPathName, lpSecurityAttributes):
        lw.debug("enter CreateDirectoryW")
        try:
            lw.debug("name: %s", self.state.mem[lpPathName].string.concrete)
            if lpPathName == "" :
                return 0
        except:
            lw.debug("name is not concrete")

        return 1

