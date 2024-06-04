import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
import angr


class clone(angr.SimProcedure):
    def run(self, arg1, arg2, arg3, arg4, arg5, arg6, arg7):
        # TODO : Return value depending on option choosen
        return self.state.solver.BVV(1338, self.state.arch.bits)
