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


class BlockInput(angr.SimProcedure):
    def run(
        self,
        fBlockIt
    ):
        return 0x1
