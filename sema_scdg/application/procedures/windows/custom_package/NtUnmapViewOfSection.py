import logging
import angr
import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class NtUnmapViewOfSection(angr.SimProcedure):
    def run(
        self,
        ProcessHandle,
        BaseAddress
    ):
        return 0x0
