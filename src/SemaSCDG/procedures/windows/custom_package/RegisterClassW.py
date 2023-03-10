import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class RegisterClassW(angr.SimProcedure):

    def run(
        self,
        lpWndClass
    ):
        return self.state.solver.BVS("retval_{}".format(self.display_name),  self.arch.bits)
