import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class GetStringTypeW(angr.SimProcedure):
    def run(self, dwInfoType, lpSrcStr, cchSrc, lpCharType):
        return 1
