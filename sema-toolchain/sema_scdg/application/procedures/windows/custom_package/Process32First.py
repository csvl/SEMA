import logging
import angr

import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class Process32First(angr.SimProcedure):

    def run(self, hSnapshot, lppe):
        processentry = self.state.solver.BVV(0x0,296)
        self.state.memory.store(lppe, processentry)
        processid = self.state.solver.BVV("aa")
        self.state.memory.store(lppe+8, processid)
        processname = self.state.solver.BVV("explorer.exe")
        self.state.memory.store(lppe+36, processname)
        return 0x1
