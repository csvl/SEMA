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


class GetStringTypeA(angr.SimProcedure):
    def run(self, dwInfoType, lpSrcStr, cchSrc, lpCharType):
        return 1
