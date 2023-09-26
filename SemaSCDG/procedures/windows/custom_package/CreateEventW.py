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
        ret_val = self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
        self.state.solver.add(ret_val > 0x0)
        return ret_val
