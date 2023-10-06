import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class SetEndOfFile(angr.SimProcedure):
    def run(self, hFile):
        return 1
