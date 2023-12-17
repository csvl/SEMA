import logging
import angr

import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class TerminateProcess(angr.SimProcedure):
    NO_RET = True
    def run(self, handle, exit_code):
        self.exit(exit_code)
