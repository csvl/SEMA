import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
import angr
import logging
import os

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)

class inet_addr(angr.SimProcedure):

    def run(self, cp):
        try:
            print(self.state.mem[cp].string.concrete)
        except:
            print(self.state.memory.load(cp,0x20))
        return 123456
