import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
import angr

class WaitForMultipleObjects(angr.SimProcedure):
    def run(self, handles, wait_all, timeout):
        return 0x00000000 #self.state.solver.BVV(angr.sim_type.SimTypeLength.from_arch(self.state.arch).size, 0)
