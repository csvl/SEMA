import angr


class FindRessourceA(angr.SimProcedure):
    def run(self, pMessage, ar2, ar3):
        return self.state.solver.BVS(
            "retval_{}".format(self.display_name), self.arch.bits
        )
