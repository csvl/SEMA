import logging
import angr

import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class CloseHandle(angr.SimProcedure):
    def run(self, hObject):
        return 0x1
