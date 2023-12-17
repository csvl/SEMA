import logging
import angr
import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class NtSetContextThread(angr.SimProcedure):
    def run(
        self,
        ThreadHandle,
        Context
    ):
        return 0x0
