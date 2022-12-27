import logging
import angr
lw = logging.getLogger("CustomSimProcedureWindows")


class NtTerminateProcess(angr.SimProcedure):
    def run(
        self,
        ProcessHandle,
        ExitStatus
    ):
        return 0x0
