import logging
import angr

import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class ShellExecuteExW(angr.SimProcedure):

    def run(
        self,
        pExecInfo
    ):
        return 0x1
