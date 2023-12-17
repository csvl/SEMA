import logging
import angr
import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class BlockInput(angr.SimProcedure):
    def run(
        self,
        fBlockIt
    ):
        return 0x1
