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


class GetTempPathW(angr.SimProcedure):
    def run(self, nBufferLength, lpBuffer):
        lw.debug("GetTempPathW.run")
        temp_path = "C:\\Temp\\"
        self.state.memory.store(lpBuffer, "C:\\Temp\\".encode(), endness="Iend_LE")
        return self.state.solver.BVV(len("C:\\Temp\\"), self.arch.bits)
