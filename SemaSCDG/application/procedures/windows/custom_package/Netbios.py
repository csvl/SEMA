import logging
import angr
lw = logging.getLogger("CustomSimProcedureWindows")


class Netbios(angr.SimProcedure):
    def run(
        self,
        pncb
    ):
        return 0x0
