import logging
import angr

import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class getaddrinfo(angr.SimProcedure):
    def run(self, pNodeName, pServiceName, pHints, ppResult):
        return 0x0
