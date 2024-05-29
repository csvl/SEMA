import logging
import angr

import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class GetStringTypeW(angr.SimProcedure):
    def run(self, dwInfoType, lpSrcStr, cchSrc, lpCharType):
        return 1
