import logging
import angr

import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class GetLogicalDrives(angr.SimProcedure):
    def run(self):
        return 0x7
