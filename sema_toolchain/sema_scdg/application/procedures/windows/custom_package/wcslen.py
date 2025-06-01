import logging
import os
import sys


import angr
try:
    lw = logging.getLogger("CustomSimProcedureLinux")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)

class wcslen(angr.SimProcedure):
    def run(self, string):
        lw.debug("wslen.run")
        maxLen = 1024
        try:

            for i in range(maxLen):
                char = self.state.memory.load(string + i * 2, 2, endness="Iend_LE")
                lw.debug(char)
                if self.state.solver.eval(char) == 0:
                    return i

        except:
            pass

        return self.state.solver.BVS(
            "retval_{}".format(self.display_name), self.arch.bits
        )