import logging
import angr
lw = logging.getLogger("CustomSimProcedureWindows")


class NtSetContextThread(angr.SimProcedure):
    def run(
        self,
        ThreadHandle,
        Context
    ):
        return 0x0
