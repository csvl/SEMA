import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
import angr


class rt_sigaction(angr.SimProcedure):
    def run(self, addr, length):  # pylint:disable=arguments-differ,unused-argument
        # TODO: actually do something
        return self.state.solver.BVV(0, self.state.arch.bits)
