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


class StartServiceCtrlDispatcherA(angr.SimProcedure):
    def run(self, lpServiceStartTable):
        lw.debug("Starting Service Control Dispatcher")
        b = self.state.arch.bytes
        lpServiceName = self.state.memory.load(lpServiceStartTable, b)
        lw.debug(lpServiceName)

        lpServiceProc = self.state.memory.load(lpServiceStartTable + b, b, endness='Iend_LE')
        lw.debug(lpServiceProc)


        self.jump(self.state.solver.eval(lpServiceProc))


        return self.state.solver.BVV(1, self.arch.bits)