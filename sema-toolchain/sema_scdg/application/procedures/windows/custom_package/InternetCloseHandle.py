import logging
import angr

import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class InternetCloseHandle(angr.SimProcedure):
    def run(self, hInternet):
        return 0x1
