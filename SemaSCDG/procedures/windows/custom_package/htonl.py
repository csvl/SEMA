import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class htonl(angr.SimProcedure):
    def run(self, hostlong):
        return hostlong
