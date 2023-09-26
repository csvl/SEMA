import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class ShellExecuteW(angr.SimProcedure):

    def run(
        self,
        hwnd,
        lpOperation,
        lpFile,
        lpParameters,
        lpDirectory,
        nShowCmd
    ):
        return 0x20
