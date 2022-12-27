import angr
import logging


class memcpy(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, dest, src, count):
        if count.symbolic:
            self.state.memory.store(dest, self.state.memory.load(src, 0x20))
            return dest
           
        else:
            self.state.memory.store(dest, self.state.memory.load(src, self.state.solver.eval(count)))
            return dest
