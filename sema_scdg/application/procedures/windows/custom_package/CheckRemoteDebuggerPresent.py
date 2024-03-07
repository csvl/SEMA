import logging
import angr
import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class CheckRemoteDebuggerPresent(angr.SimProcedure):
    def run(
        self,
        hProcess,
        pbDebuggerPresent
    ):
        dbg = self.state.solver.BVV(0, self.arch.bits)
        self.state.memory.store(pbDebuggerPresent, dbg)
        return 0x1
