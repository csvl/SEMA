import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")

class CreateMutexA(angr.SimProcedure):
    def run(self, lpMutexAttributes, bInitialOwner, lpName):
        error = self.state.solver.BVS("error", self.arch.bits)
        self.state.solver.add(error != 0xb7)
        self.state.globals["GetLastError"] = error
        retval = self.state.solver.BVS(
            "retval_{}".format(self.display_name), self.arch.bits
        )
        self.state.solver.add(retval > 0)
        return retval
