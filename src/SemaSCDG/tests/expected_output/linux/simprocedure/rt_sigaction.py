import angr


class rt_sigaction(angr.SimProcedure):
    def run(self, addr, length):  # pylint:disable=arguments-differ,unused-argument
        # TODO: actually do something
        return self.state.solver.BVV(0, self.state.arch.bits)
