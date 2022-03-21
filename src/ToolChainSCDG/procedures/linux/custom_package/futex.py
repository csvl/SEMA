import angr


class futex(angr.SimProcedure):
    # https://github.com/spotify/linux/blob/master/include/linux/futex.h
    def run(self, uaddr, futex_op, val, timeout, uaddr2, val3):
        op = self.state.solver.eval(futex_op)

        if op & 1:  # FUTEX_WAKE
            # l.debug('futex(FUTEX_WAKE)')
            return self.state.solver.Unconstrained(
                "futex", self.state.arch.bits, key=("api", "futex")
            )
        else:
            # l.debug('futex(futex_op=%d)', op)
            return self.state.solver.Unconstrained(
                "futex", self.state.arch.bits, key=("api", "futex")
            )
