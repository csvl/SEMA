import logging
import angr
import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class NtGetContextThread(angr.SimProcedure):
    def run(
        self,
        ThreadHandle,
        pContext
    ):
        return 0x0
