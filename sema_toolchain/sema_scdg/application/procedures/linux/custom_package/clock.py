import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
import angr
import time as timer


class clock(angr.SimProcedure):
    def run(self):
        n_clock = int(timer.clock() * 1000)
        return n_clock
