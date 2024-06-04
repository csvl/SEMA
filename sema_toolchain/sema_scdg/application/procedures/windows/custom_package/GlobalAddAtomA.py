import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
import angr


class GlobalAddAtomA(angr.SimProcedure):
    def run(self, pMessage):
        return self.state.solver.BVS(
            "retval_{}".format(self.display_name), self.arch.bits
        )
