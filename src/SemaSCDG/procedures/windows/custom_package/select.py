import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class select(angr.SimProcedure):
    def run(self, nfds, readfds, writefds, exceptfds, timeout):
        retval = self.state.solver.BVS(
            "retval_{}".format(self.display_name), self.arch.bits
        )
        self.state.solver.add(self.state.solver.SGT(retval,0))
        return retval
