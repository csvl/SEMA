import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
import angr
class ResumeThread(angr.SimProcedure):
    def run(self, hThread):
        # Do nothing - return value not needed for symbolic execution
        r = self.state.solver.BVS('ret_{}'.format(self.display_name), self.arch.bits)
        self.state.solver.add(r >= 0)
        self.state.solver.add(r <= 4)
        return r
