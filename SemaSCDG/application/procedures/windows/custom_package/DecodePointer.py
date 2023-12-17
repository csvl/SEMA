import logging
import angr

import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class DecodePointer(angr.SimProcedure):
    def run(self, ptr):
        lw.debug("DecodePointer: Hello")
        return ptr
