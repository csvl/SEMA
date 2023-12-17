import logging
import angr

import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class PathFileExistsA(angr.SimProcedure):
    def run(self, pszPath):
        try:
            print(self.state.mem[pszPath].string.concrete)
        except:
            print(self.state.memory.load(pszPath,0x20))
        return 0x1
