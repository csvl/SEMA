import angr


class write(angr.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, fd, src, length):
        simfd = self.state.posix.get_fd(fd)
        if simfd is None:
            return -1
        # length = self.state.solver.eval(length)
        return simfd.write(src, length)
