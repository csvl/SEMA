import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class WinExec(angr.SimProcedure):

    def run(
        self,
        lpCmdLine,
        uCmdShow
    ):
        return 0x20
