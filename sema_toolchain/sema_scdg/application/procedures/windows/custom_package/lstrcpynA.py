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


class lstrcpynA(angr.SimProcedure):
    def run(self, lpstring1, lpstring2, iMaxLength):
        if lpstring1.symbolic or lpstring2.symbolic or iMaxLength.symbolic:
            return lpstring1

        nchar = self.state.solver.eval(iMaxLength)

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

        new_str = second_str[: nchar - 1] + "\0"
        new_str = self.state.solver.BVV(new_str)
        self.state.memory.store(lpstring1, new_str)
        return lpstring1
