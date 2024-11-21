import os
import sys


import logging
import angr
import os

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)

class GetCommandLineA(angr.SimProcedure):
    def run(self):
        return self.project.simos.acmdln_ptr
