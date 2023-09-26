import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class StartServiceA(angr.SimProcedure):
    def run(self, hService,dwNumServiceArgs,lpServiceArgVectors):
        retval = self.state.solver.BVS(
            "retval_{}".format(self.display_name), self.arch.bits
        )
        self.state.solver.add(retval != 0)
        return retval
