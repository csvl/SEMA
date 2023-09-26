import logging
import angr
lw = logging.getLogger("CustomSimProcedureWindows")


class IsDebuggerPresent(angr.SimProcedure):
    def run(
        self
    ):
        return 0x0
