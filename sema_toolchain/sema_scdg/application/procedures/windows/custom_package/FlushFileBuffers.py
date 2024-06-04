import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
import angr

class FlushFileBuffers(angr.SimProcedure):
    def run(self, handle):
        # Simulate successful return
        return 1
