import angr
import logging
import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])

class getsockname(angr.SimProcedure):

    def run(self, s, name, namelen):
        return 0x0
