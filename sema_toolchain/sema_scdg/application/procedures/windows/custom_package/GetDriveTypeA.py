import os
import sys


import logging
import angr

import os

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)


class GetDriveTypeA(angr.SimProcedure):
    def run(self, lpRootPathName):
        return 0x3
