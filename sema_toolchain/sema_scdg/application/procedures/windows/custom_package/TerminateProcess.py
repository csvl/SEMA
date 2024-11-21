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


class TerminateProcess(angr.SimProcedure):
    NO_RET = True
    def run(self, handle, exit_code):
        self.exit(exit_code)
