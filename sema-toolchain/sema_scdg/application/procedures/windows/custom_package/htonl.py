import logging
import angr

import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class htonl(angr.SimProcedure):
    def run(self, hostlong):
        return hostlong
