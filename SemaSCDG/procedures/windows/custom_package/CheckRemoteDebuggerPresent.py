import logging
import angr
lw = logging.getLogger("CustomSimProcedureWindows")


class CheckRemoteDebuggerPresent(angr.SimProcedure):
    def run(
        self,
        hProcess,
        pbDebuggerPresent
    ):
        dbg = self.state.solver.BVV(0, self.arch.bits)
        self.state.memory.store(pbDebuggerPresent, dbg)
        return 0x1
