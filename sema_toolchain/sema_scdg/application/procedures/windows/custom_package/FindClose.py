import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
import angr
import claripy


class FindClose(angr.SimProcedure):
    def run(self, hFindFile):
        return 0x1
