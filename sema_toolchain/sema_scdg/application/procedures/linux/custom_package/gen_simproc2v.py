import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
import angr


class gen_simproc2v(angr.SimProcedure):
    def run(self, arg1, arg2):
        return
