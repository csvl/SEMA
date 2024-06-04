import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
import logging
import angr
from cle.backends.externs.simdata.io_file import io_file_data_for_arch

import os

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)


class FormatMessageA(angr.SimProcedure):
    def run(self, dwFlags, lpSource, dwMessageId, dwLanguageId, lpBuffer, nSize, Arguments):
        ptr=self.state.solver.BVS("lpBuffer",8*self.state.solver.eval(nSize))
        self.state.memory.store(lpBuffer,ptr)
        return self.state.solver.eval(nSize) - 1
