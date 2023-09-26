import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class GetThreadUILanguage(angr.SimProcedure):

    def run(self):
        return 0x1400
