import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class RegisterClassA(angr.SimProcedure):

    def run(
        self,
        unnamedParam1
    ):
        return self.state.solver.BVS("retval_{}".format(self.display_name),  self.arch.bits)
