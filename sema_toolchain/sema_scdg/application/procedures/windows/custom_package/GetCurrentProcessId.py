import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
import angr

class GetCurrentProcessId(angr.SimProcedure):
    def run(self):
        return 0x1337BEE2
