import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class InitCommonControlsEx(angr.SimProcedure):
    def run(self, ptr):
        return self.state.solver.BVS(
            "retval_{}".format(self.display_name), self.arch.bits
        )
