import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class atoi(angr.SimProcedure):
    def run(self, string):
        # import pdb; pdb.set_trace()
        if string.symbolic:
            return self.state.solver.BVS(
                "retval_{}".format(self.display_name), self.arch.bits
            )
        second_str = self.state.solver.eval(string)
        print(second_str)
        return second_str
