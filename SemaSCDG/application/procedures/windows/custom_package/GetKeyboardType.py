import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class GetKeyboardType(angr.SimProcedure):
    def run(self,nTypeFlag):
        return 0x4
