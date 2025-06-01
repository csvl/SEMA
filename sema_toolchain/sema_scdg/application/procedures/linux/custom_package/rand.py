import os
import sys

import angr
import logging

try:
    lw = logging.getLogger("CustomSimProcedureLinux")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)

class rand(angr.SimProcedure):
    def run(self):
        #lw.debug('&'*100)
        lw.debug('using custom random (0)')
        #rval = self.state.solver.BVV(0, 32)
        #rval = self.state.solver.BVS("rand", 31, key=("api", "rand"))
        #lw.debug(f'int size: {self.arch.sizeof["int"]}')
        #lw.debug('&'*100)
        return 0 # rval.zero_extend(self.arch.sizeof["int"] - 31) self.state.solver.BVV(0, 32)  # rval.zero_extend(self.arch.sizeof["int"] - 31)
