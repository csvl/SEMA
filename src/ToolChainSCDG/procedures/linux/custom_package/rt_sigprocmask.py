import angr


class rt_sigprocmask(angr.SimProcedure):
    def run(self, how, set_, oldset, sigsetsize):
        return 0
        # TODO: EFAULT
        return self.state.solver.If(
            self.state.solver.And(
                how != self.state.posix.SIG_BLOCK,
                how != self.state.posix.SIG_UNBLOCK,
                how != self.state.posix.SIG_SETMASK,
            ),
            self.state.solver.BVV(self.state.posix.EINVAL, self.state.arch.bits),
            self.state.solver.BVV(0, self.state.arch.bits),
        )
