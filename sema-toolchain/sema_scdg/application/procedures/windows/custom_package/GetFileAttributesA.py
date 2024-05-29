import logging
import angr

import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class GetFileAttributesA(angr.SimProcedure):
    def run(self, lpFileName):
        try:
            print(self.state.mem[lpFileName].string.concrete)
        except:
            print(self.state.memory.load(lpFileName,0x20))
        return -1  #fail pour gh0strat
