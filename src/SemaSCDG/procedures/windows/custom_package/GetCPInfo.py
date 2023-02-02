import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class GetCPInfo(angr.SimProcedure):
    def run(self, CodePage,lpCPInfo):
        return 0x1
