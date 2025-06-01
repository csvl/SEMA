import os
import sys


import logging
import angr

import os

import claripy

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


        retval = self.state.solver.BVS(
            "retval_{}".format(self.display_name), self.arch.bits
        )
        #return -1  #fail pour gh0strat
        return retval