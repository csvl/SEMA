import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class GetUserNameA(angr.SimProcedure):
    def get_username(self, size):
        return ("CharlyBVO"[: size - 1] + "\0").encode("utf-8")

    def run(self, lpBuffer, lpnSize):
        if lpBuffer.symbolic:
            return self.state.solver.BVS(
                "retval_{}".format(self.display_name), self.arch.bits
            )

        buf = self.state.solver.eval(lpBuffer)
        if buf != 0:
            size = 0
            # TODO : Think about this case
            if lpnSize.symbolic:
                size = 12
            else:
                size = self.state.mem[lpnSize].int.concrete
            user_str = self.get_username(size)
            user_bvv = self.state.solver.BVV(user_str)
            self.state.memory.store(
                lpBuffer, user_bvv
            )  # ,endness=self.arch.memory_endness)
            self.state.memory.store(
                lpnSize, self.state.solver.BVV(len(user_str), self.arch.bits)
            )  # ,endness=self.arch.memory_endness)
        return self.state.solver.BVS(
            "retval_{}".format(self.display_name), self.arch.bits
        )
