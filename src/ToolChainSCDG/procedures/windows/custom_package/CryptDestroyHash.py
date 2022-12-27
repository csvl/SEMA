import logging
import angr
lw = logging.getLogger("CustomSimProcedureWindows")


class CryptDestroyHash(angr.SimProcedure):
    def run(
        self,
        hHash
    ):
        return 0x1
