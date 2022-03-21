import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class SysFreeString(angr.SimProcedure):
    def run(self, bstrString):
        if bstrString.symbolic:
            return self.state.solver.BVS(
                "retval_{}".format(self.display_name), self.arch.bits
            )
        self.state.heap.free(self.state.solver.eval(bstrString))
