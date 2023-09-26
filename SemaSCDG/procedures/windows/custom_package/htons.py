import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class htons(angr.SimProcedure):
    def run(self, hostlong):
        return hostlong
