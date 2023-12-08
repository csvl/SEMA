import angr

from .socket import socket
from .connect import connect
from .getsockname import getsockname
from .gen_simproc3 import gen_simproc3
from .gen_simproc4 import gen_simproc4
from .sendto import sendto


class socketcall(angr.SimProcedure):
    # http://jkukunas.blogspot.com/2010/05/x86-linux-networking-system-calls.html
    def run(self, num_syscall, args):
        num = self.state.solver.eval(num_syscall)
        # SOCKET : 3 args
        if num == 1:
            args = self.state.mem[args].long.array(3)
            # import pdb; pdb.set_trace()
            self.ret_expr = self.inline_call(
                socket, args[0].resolved, args[1].resolved, args[2].resolved
            ).ret_expr
            retval = self.ret_expr
        # BIND
        elif num == 2:
            args = self.state.mem[args].long.array(3)
            retval = self.inline_call(
                angr.SIM_PROCEDURES["posix"]["bind"],
                args[0].resolved,
                args[1].resolved,
                args[2].resolved,
            ).ret_expr
            self.ret_expr = retval
        # CONNECT
        elif num == 3:
            args = self.state.mem[args].long.array(3)
            retval = self.inline_call(
                connect, args[0].resolved, args[1].resolved, args[2].resolved
            ).ret_expr
            self.ret_expr = retval
        # LISTEN
        elif num == 4:
            args = self.state.mem[args].long.array(2)
            retval = self.inline_call(
                angr.SIM_PROCEDURES["posix"]["listen"],
                args[0].resolved,
                args[1].resolved,
            ).ret_expr
            self.ret_expr = retval
        # ACCEPT
        elif num == 5:
            args = self.state.mem[args].long.array(3)
            retval = self.inline_call(
                angr.SIM_PROCEDURES["posix"]["accept"],
                args[0].resolved,
                args[1].resolved,
                args[2].resolved,
            ).ret_expr
            self.ret_expr = retval
        # GETSOCKNAME
        elif num == 6:
            args = self.state.mem[args].long.array(3)
            retval = self.inline_call(
                getsockname, args[0].resolved, args[1].resolved, args[2].resolved
            ).ret_expr
            self.ret_expr = retval
        # GETPEERNAME
        elif num == 7:
            args = self.state.mem[args].long.array(3)
            retval = self.inline_call(
                gen_simproc3, args[0].resolved, args[1].resolved, args[2].resolved
            ).ret_expr
            self.ret_expr = retval
        # SOCKETPAIR
        elif num == 8:
            args = self.state.mem[args].long.array(4)
            retval = self.inline_call(
                gen_simproc4,
                args[0].resolved,
                args[1].resolved,
                args[2].resolved,
                args[3].resolved,
            ).ret_expr
            self.ret_expr = retval
        # SEND
        elif num == 9:
            args = self.state.mem[args].long.array(4)
            retval = self.inline_call(
                angr.SIM_PROCEDURES["posix"]["send"],
                args[0].resolved,
                args[1].resolved,
                args[2].resolved,
                args[3].resolved,
            ).ret_expr
            self.ret_expr = retval
        # RECV
        elif num == 10:
            args = self.state.mem[args].long.array(4)
            retval = self.inline_call(
                angr.SIM_PROCEDURES["posix"]["recv"],
                args[0].resolved,
                args[1].resolved,
                args[2].resolved,
                args[3].resolved,
            ).ret_expr
            self.ret_expr = retval
        # SENDTO
        elif num == 11:
            args = self.state.mem[args].long.array(6)
            retval = self.inline_call(
                sendto,
                args[0].resolved,
                args[1].resolved,
                args[2].resolved,
                args[3].resolved,
                args[4].resolved,
                args[5].resolved,
            ).ret_expr
            self.ret_expr = retval
        # RECVFROM
        elif num == 12:
            args = self.state.mem[args].long.array(6)
            retval = self.inline_call(
                angr.SIM_PROCEDURES["posix"]["recvfrom"],
                args[0].resolved,
                args[1].resolved,
                args[2].resolved,
                args[3].resolved,
                args[4].resolved,
                args[5].resolved,
            ).ret_expr
            self.ret_expr = retval
        # SETSOCKOPT
        elif num == 14:
            args = self.state.mem[args].long.array(5)
            retval = self.inline_call(
                angr.SIM_PROCEDURES["posix"]["setsockopt"],
                args[0].resolved,
                args[1].resolved,
                args[2].resolved,
                args[3].resolved,
                args[4].resolved,
            ).ret_expr
            self.ret_expr = retval

        # GETSOCKOPT
        elif num == 15:
            args = self.state.mem[args].long.array(5)
            retval = self.inline_call(
                angr.SIM_PROCEDURES["posix"]["getsockopt"],
                args[0].resolved,
                args[1].resolved,
                args[2].resolved,
                args[3].resolved,
                args[4].resolved,
            ).ret_expr
            self.ret_expr = retval
        else:
            retval = self.state.solver.Unconstrained(
                "unconstrained_ret_%s" % self.display_name,
                self.state.arch.bits,
                key=("api", "?", self.display_name),
            )

        return retval
