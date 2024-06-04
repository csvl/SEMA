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


class atoi(angr.SimProcedure):
    def run(self, string):
        # import pdb; pdb.set_trace()
        if string.symbolic:
            return self.state.solver.BVS(
                "retval_{}".format(self.display_name), self.arch.bits
            )
        second_str = self.state.solver.eval(string)
        print(second_str)
        return second_str
