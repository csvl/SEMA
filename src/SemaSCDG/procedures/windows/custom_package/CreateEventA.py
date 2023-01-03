import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class CreateEventA(angr.SimProcedure):

    def run(
        self,
        lpEventAttributes,
        bManualReset,
        bInitialState,
        lpName
    ):
        return self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
