import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class ntohs(angr.SimProcedure):
    def run(self, netshort):
        return netshort
