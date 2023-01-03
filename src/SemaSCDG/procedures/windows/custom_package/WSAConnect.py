import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class WSAConnect(angr.SimProcedure):
    def run(self, s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS):
        return 0x0
