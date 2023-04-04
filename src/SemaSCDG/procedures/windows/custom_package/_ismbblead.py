import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class _ismbblead(angr.SimProcedure):
    def run(self, c):
        return 0x0
