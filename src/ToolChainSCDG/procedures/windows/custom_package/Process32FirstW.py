import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class Process32FirstW(angr.SimProcedure):
        
    def run(self, hSnapshot, lppe):
        return 0x0
