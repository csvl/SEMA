import logging
import angr

import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class GetDriveTypeA(angr.SimProcedure):
    def run(self, lpRootPathName):
        return 0x3
