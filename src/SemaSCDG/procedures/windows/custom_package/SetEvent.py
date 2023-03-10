import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class SetEvent(angr.SimProcedure):
    def run(self, hEvent):
        return 0x1
