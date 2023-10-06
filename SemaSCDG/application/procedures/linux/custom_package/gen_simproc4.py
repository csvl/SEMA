import angr


class gen_simproc4(angr.SimProcedure):
    def run(self, arg1, ar2, arg3, arg4, resolves=None):

        return self.state.solver.Unconstrained(
            "unconstrained_ret_%s" % self.display_name,
            self.state.arch.bits,
            key=("api", "?", self.display_name),
        )

    def __repr__(self):
        if "resolves" in self.kwargs:
            return "<Syscall stub (%s)>" % self.kwargs["resolves"]
        else:
            return "<Syscall stub>"
