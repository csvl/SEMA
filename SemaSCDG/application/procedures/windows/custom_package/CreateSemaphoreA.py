import logging
import angr
lw = logging.getLogger("CustomSimProcedureWindows")

class CreateSemaphoreA(angr.SimProcedure):

    def run(
        self,
        lpSemaphoreAttributes,
        lInitialCount,
        lMaximumCount,
        lpName
    ):
        handle = self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
        self.state.solver.add(handle != 0)
        return handle
