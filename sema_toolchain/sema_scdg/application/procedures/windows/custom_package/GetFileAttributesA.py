import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
import logging
import angr

import os

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)


class GetFileAttributesA(angr.SimProcedure):
    def run(self, lpFileName):
        try:
            print(self.state.mem[lpFileName].string.concrete)
        except:
            print(self.state.memory.load(lpFileName,0x20))
        return -1  #fail pour gh0strat
