import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
import angr

class FreeLibrary(angr.SimProcedure):
    def run(self, h_module):
        # Return 1 on success
        return 1
