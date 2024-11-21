import os
import sys


import logging
import angr

import os

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)


class WSAConnect(angr.SimProcedure):
    def run(self, s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS):
        return 0x0
