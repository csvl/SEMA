import logging
import angr
import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class NtResumeThread(angr.SimProcedure):
    def run(
        self,
        ThreadHandle,
        SuspendCount
    ):
        return 0x0
