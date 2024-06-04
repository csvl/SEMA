import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
import angr

class DeleteFileW(angr.SimProcedure):
    def run(self, file_path_ptr):
        return 0x1
