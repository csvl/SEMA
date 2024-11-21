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


class InternetCloseHandle(angr.SimProcedure):
    def run(self, hInternet):
        return 0x1
