import angr


class getsockname(angr.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, sock_fd, addr, length):  # pylint:disable=unused-argument
        len_addr = self.state.mem[length].int.concrete
        for i in range(len_addr):
            self.state.memory.store(
                addr + i,
                self.state.solver.BVS(
                    "sockname_" + str(i),
                    8,
                    key=("api", "getsockname", "sockname_" + str(i)),
                ),
                endness="Iend_LE",
            )
        # self.state.solver.Unconstrained("unconstrained_ret_%s" % self.display_name, 8*len_addr, key=('api', '?', self.display_name))
        return 0
