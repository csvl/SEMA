import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
import angr

class GetConsoleWindow(angr.SimProcedure):
    def run(self):
        # Return a dummy window handle value (0x12345678 in this case)
        # return self.state.solver.BVV(0x12345678, self.state.arch.bits)
        return None
