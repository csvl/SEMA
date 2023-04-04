import angr
import logging
lw = logging.getLogger("CustomSimProcedureWindows")

class getsockname(angr.SimProcedure):

    def run(self, s, name, namelen):
        return 0x0
