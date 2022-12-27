import logging
import angr
lw = logging.getLogger("CustomSimProcedureWindows")


class NtGetContextThread(angr.SimProcedure):
    def run(
        self,
        ThreadHandle,
        pContext
    ):
        return 0x0
