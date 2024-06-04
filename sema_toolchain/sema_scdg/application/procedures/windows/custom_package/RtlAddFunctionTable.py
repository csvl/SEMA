import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
import angr

class RtlAddFunctionTable(angr.SimProcedure):
    def run(self, pFunctionTable, dwEntryCount, dwBaseAddress):
        # We can just return STATUS_SUCCESS (0) as the simulated return value
        return 0
