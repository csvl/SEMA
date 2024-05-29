import logging
import angr

import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class ntohs(angr.SimProcedure):
    def run(self, netshort):
        return netshort
