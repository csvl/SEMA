import os
import sys


import angr
import logging
import os

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)

class inet_ntoa(angr.SimProcedure):

    def run(self, addr):
        self.state.memory.store(0x666666,"192.168.1.1")
        return 0x666666
