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


class InternetReadFile(angr.SimProcedure):
    def run(self, InternetReadFile, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead):

        if dwNumberOfBytesToRead.symbolic or self.state.solver.eval(dwNumberOfBytesToRead) > 0x10:
            ptr=self.state.solver.BVS("lpBuffer",8*0x10,key=("buffer", hex(self.state.globals["n_buffer"])),eternal=True)
            self.state.memory.store(lpBuffer,ptr)

        else:
            ptr=self.state.solver.BVS("lpBuffer",8*self.state.solver.eval(dwNumberOfBytesToRead),key=("buffer", hex(self.state.globals["n_buffer"])),eternal=True)
            self.state.memory.store(lpBuffer,ptr)

        self.state.globals["n_buffer"] = self.state.globals["n_buffer"] + 1
        return 0x1
