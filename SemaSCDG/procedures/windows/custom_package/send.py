import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class send(angr.SimProcedure):
    def run(self, s, buf, length, flags):
        if length.symbolic:
            return self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)           
        else:
            length = self.state.solver.eval(length)
            return length
