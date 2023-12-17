import logging
import angr

import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class _ismbblead(angr.SimProcedure):
    def run(self, c):
        return 0x0
