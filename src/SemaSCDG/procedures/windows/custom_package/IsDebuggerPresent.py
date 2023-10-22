import logging
import angr
lw = logging.getLogger("CustomSimProcedureWindows")


class IsDebuggerPresent(angr.SimProcedure):
    def run(
        self
    ):
        # return 0x0
        val = self.state.solver.Unconstrained(
                "retval_{}".format(self.display_name), self.arch.bits
            )
        return val
