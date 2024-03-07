import logging
import angr
import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class CryptDestroyHash(angr.SimProcedure):
    def run(
        self,
        hHash
    ):
        return 0x1
