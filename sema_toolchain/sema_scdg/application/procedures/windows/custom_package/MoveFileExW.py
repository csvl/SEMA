import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
import angr

class MoveFileExW(angr.SimProcedure):
    def run(self, lpExistingFileName, lpNewFileName, dwFlags):
        # We don't actually want to perform the file move during symbolic execution,
        # so we just return a success status
        return 0x1
