import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class getaddrinfo(angr.SimProcedure):
    def run(self, pNodeName, pServiceName, pHints, ppResult):
        return 0x0
