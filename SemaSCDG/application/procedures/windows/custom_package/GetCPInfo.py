import logging
import angr

import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class GetCPInfo(angr.SimProcedure):
    def run(self, CodePage,lpCPInfo):
        return 0x1
