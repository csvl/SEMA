import logging
import angr

import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class GetKeyboardType(angr.SimProcedure):
    def run(self,nTypeFlag):
        return 0x4
