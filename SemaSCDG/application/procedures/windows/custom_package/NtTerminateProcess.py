import logging
import angr
import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class NtTerminateProcess(angr.SimProcedure):
    def run(
        self,
        ProcessHandle,
        ExitStatus
    ):
        return 0x0
