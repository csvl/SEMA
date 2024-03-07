import angr


class openat(angr.SimProcedure):
    def run(self, p_dir, p_addr, flags, mode):
        strlen = angr.SIM_PROCEDURES["libc"]["strlen"]

        p_strlen = self.inline_call(strlen, p_addr)
        p_expr = self.state.memory.load(
            p_addr, p_strlen.max_null_index, endness="Iend_BE"
        )
        path = self.state.solver.eval(p_expr, cast_to=bytes)
        # import pdb; pdb.set_trace()
        fda = self.state.posix.open(path, flags)
        if fda is None:
            return -1
        return fda
