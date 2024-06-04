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


class GetWindowsDirectoryW(angr.SimProcedure):
    def run(self, lpBuffer, uSize):
        size = self.state.solver.eval(uSize)
        path = self.state.solver.BVV(b'C\x00:\x00\\\x00W\x00i\x00n\x00d\x00o\x00w\x00s\x00\x00\x00')
        self.state.memory.store(lpBuffer, path)
        return 20
