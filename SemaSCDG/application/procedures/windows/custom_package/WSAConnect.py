import logging
import angr

import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class WSAConnect(angr.SimProcedure):
    def run(self, s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS):
        return 0x0
