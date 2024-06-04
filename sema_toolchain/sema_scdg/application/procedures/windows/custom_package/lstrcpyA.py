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


class lstrcpyA(angr.SimProcedure):
    def run(self, lpstring1, lpstring2):
        if lpstring1.symbolic or lpstring2.symbolic:
            return lpstring1

        try:
            second_str = self.state.mem[lpstring2].string.concrete
        except:
            lw.debug("lpstring2 not resolvable")
            second_str = ""

        try:
            second_str = second_str.decode("utf-8")
        except:
            lw.debug("string2 not decodable")
            second_str = ""

        new_str = second_str + "\0"
        new_str = self.state.solver.BVV(new_str)
        self.state.memory.store(lpstring1, new_str)
        return lpstring1
