import angr
from .write import write


class writev(angr.SimProcedure):
    def run(self, fd, iovec, iovcnt):
        angr.sim_type.register_types(
            angr.sim_type.parse_types(
                """
        struct iovec {
            void  *iov_base;    /* Starting address */
            size_t iov_len;     /* Number of bytes to transfer */
        };
        """
            )
        )
        if iovec.symbolic or iovcnt.symbolic:
            raise angr.errors.SimPosixError("Can't handle symbolic arguments to writev")
        iovcnt = self.state.solver.eval(iovcnt)
        iovec = self.state.solver.eval(iovec)
        res = self.state.solver.Unconstrained(
            "unconstrained_ret_%s" % self.display_name,
            self.state.arch.bits,
            key=("api", "?", self.display_name),
        )
        # import pdb; pdb.set_trace()
        for element in self.state.mem[iovec].struct.iovec.array(iovcnt).resolved:
            # import pdb; pdb.set_trace()
            tmpres = self.inline_call(
                write, fd, element.iov_base, element.iov_len
            ).ret_expr
            if self.state.solver.is_true(self.state.solver.SLT(tmpres, 0)):
                return tmpres
        # import pdb; pdb.set_trace()
        return res
