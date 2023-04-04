import logging
import angr
lw = logging.getLogger("CustomSimProcedureWindows")


class BlockInput(angr.SimProcedure):
    def run(
        self,
        fBlockIt
    ):
        return 0x1
