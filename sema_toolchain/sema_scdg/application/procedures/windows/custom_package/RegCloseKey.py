import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
import angr

class RegCloseKey(angr.SimProcedure):
    def run(self, hKey):
        # For the purposes of this simprocedure, we don't actually need to do anything.
        # We can just return an arbitrary value (in this case, 0).
        return 0
