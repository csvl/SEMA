import logging
import angr
lw = logging.getLogger("CustomSimProcedureWindows")

class GetCommandLineA(angr.SimProcedure):
    def run(self):
        return self.state.solver.BVS(
            "retval_{}".format(self.display_name), self.arch.bits
        )
