import logging
import angr

import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class GetDriveTypeW(angr.SimProcedure):
    def run(self, lpRootPathName):
        return 0x3
