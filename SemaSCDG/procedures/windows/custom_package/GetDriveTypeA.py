import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class GetDriveTypeA(angr.SimProcedure):
    def run(self, lpRootPathName):
        return 0x3
