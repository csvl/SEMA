import logging
import angr
lw = logging.getLogger("CustomSimProcedureWindows")


class NtResumeThread(angr.SimProcedure):
    def run(
        self,
        ThreadHandle,
        SuspendCount
    ):
        return 0x0
