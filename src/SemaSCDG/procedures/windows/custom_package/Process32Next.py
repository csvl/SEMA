import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class Process32Next(angr.SimProcedure):
    def run(self, hSnapshot, lppe):
        return 0x0
    
    # TODO list of usual process
