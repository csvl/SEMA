import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
import angr

class SetThreadPriority(angr.SimProcedure):
    def run(self, hThread, dwPriority):
        # Do nothing, just return success
        return 0x1
