import logging
import angr

import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class Process32Next(angr.SimProcedure):
    def run(self, hSnapshot, lppe):
        return 0x0
    
    # TODO list of usual process
