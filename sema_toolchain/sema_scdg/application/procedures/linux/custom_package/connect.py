import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
import angr


class connect(angr.SimProcedure):
    def run(self, fd, addr, addr_len):
        # TODO : Return disjonction of value (failure or success of connect)
        return 0
