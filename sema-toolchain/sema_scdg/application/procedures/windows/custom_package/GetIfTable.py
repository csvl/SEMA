import logging
import angr

import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class GetIfTable(angr.SimProcedure):
    def run(self, pIfTable, pdwSize, bOrder):
        return 0x0
