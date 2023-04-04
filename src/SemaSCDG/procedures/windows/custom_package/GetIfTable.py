import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class GetIfTable(angr.SimProcedure):
    def run(self, pIfTable, pdwSize, bOrder):
        return 0x0
