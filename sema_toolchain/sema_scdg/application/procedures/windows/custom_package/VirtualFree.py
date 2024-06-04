import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
import angr
import claripy


class VirtualFree(angr.SimProcedure):
    def run(self, lpAddress, dwSize, dwFreeType):
        return 0x1
