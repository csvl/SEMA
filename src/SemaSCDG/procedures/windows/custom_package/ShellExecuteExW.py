import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class ShellExecuteExW(angr.SimProcedure):

    def run(
        self,
        pExecInfo
    ):
        return 0x1
