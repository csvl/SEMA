import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class Process32NextW(angr.SimProcedure):
    def run(self, hSnapshot, lppe):
        return 0x0
