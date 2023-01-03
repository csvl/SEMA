import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class GetLogicalDrives(angr.SimProcedure):
    def run(self):
        return 0x7
