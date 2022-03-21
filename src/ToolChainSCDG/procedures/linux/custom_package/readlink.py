import angr


class readlink(angr.SimProcedure):
    def run(self, pathaddr, dst, length):
        strlen = angr.SIM_PROCEDURES["libc"]["strlen"]

        p_strlen = self.inline_call(strlen, pathaddr)
        p_expr = self.state.memory.load(
            pathaddr, p_strlen.max_null_index, endness="Iend_BE"
        )
        path = self.state.solver.eval(p_expr, cast_to=bytes)

        fd = self.state.posix.open(path, self.state.solver.BVV(1, self.state.arch.bits))

        simfd = self.state.posix.get_fd(fd)
        if simfd is None:

            return -1

        retval = simfd.read(dst, length)
        self.state.posix.close(fd)
        return retval
