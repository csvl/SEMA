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


class lstrcpyW(angr.SimProcedure):
    def run(self, lpstring1, lpstring2):
        if lpstring1.symbolic or lpstring2.symbolic:
            return lpstring1

        try:
            second_str = self.state.mem[lpstring2].wstring.concrete
        except:
            lw.debug("lpstring2 not resolvable")
            second_str = ""

        new_str = second_str + "\0"
        new_str = self.state.solver.BVV(new_str.encode("utf-16le"))
        self.state.memory.store(lpstring1, new_str)
        return lpstring1
