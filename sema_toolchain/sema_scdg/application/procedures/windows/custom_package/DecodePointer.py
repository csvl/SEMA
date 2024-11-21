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


class DecodePointer(angr.SimProcedure):
    def run(self, ptr):
        lw.debug("DecodePointer: Hello")
        return ptr
