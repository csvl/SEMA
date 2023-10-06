import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class StartServiceCtrlDispatcherA(angr.SimProcedure):
    def run(self, lpServiceStartTable):
        retval = self.state.solver.BVS(
            "retval_{}".format(self.display_name), self.arch.bits
        )
        self.state.solver.add(retval != 0)
        return retval
