import logging
import angr
lw = logging.getLogger("CustomSimProcedureWindows")


class NtUnmapViewOfSection(angr.SimProcedure):
    def run(
        self,
        ProcessHandle,
        BaseAddress
    ):
        return 0x0
