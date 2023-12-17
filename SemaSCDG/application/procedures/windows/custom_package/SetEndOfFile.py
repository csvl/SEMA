import logging
import angr

import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class SetEndOfFile(angr.SimProcedure):
    def run(self, hFile):
        return 1
