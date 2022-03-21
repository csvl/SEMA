import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class KiUserExceptionDispatcher(angr.SimProcedure):
    def run(self, pExceptionRec, Pcontext):
        return self.state.solver.BVS(
            "retval_{}".format(self.display_name), self.arch.bits
        )
