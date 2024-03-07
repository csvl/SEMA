import logging
import angr
import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class Netbios(angr.SimProcedure):
    def run(
        self,
        pncb
    ):
        return 0x0
