import os
import sys


import logging
import angr
import os

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)


class AfxWinMain(angr.SimProcedure):
    def run(
        self,
        arg1,
        arg2,
        arg3,
        arg4
    ):
        print(hex(self.state.solver.eval(arg1)))
        print(hex(self.state.solver.eval(arg2)))
        print(hex(self.state.solver.eval(arg3)))
        print(hex(self.state.solver.eval(self.state.memory.load(self.state.solver.eval(arg3),16))))
        print(hex(self.state.solver.eval(arg4)))
        return 0x666
