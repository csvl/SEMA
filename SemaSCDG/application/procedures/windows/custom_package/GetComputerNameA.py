import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class GetComputerNameA(angr.SimProcedure):
    def get_username(self, size):
        return ("CharlyBVO_PC"[: size - 1] + "\0").encode("utf-8")

    def run(self, lpBuffer, nSize):
        if lpBuffer.symbolic:
            return self.state.solver.BVS(
                "retval_{}".format(self.display_name), self.arch.bits
            )

        buf = self.state.solver.eval(lpBuffer)
        if buf != 0:
            size = 0
            # TODO : Think about this case
            if nSize.symbolic:
                size = 15
            else:
                size = self.state.mem[nSize].int.concrete
            user_str = self.get_username(size)
            user_bvv = self.state.solver.BVV(user_str)
            self.state.memory.store(
                lpBuffer, user_bvv
            )  # ,endness=self.arch.memory_endness)
            self.state.memory.store(
                nSize, self.state.solver.BVV(len(user_str), self.arch.bits)
            )  # ,endness=self.arch.memory_endness)
        return self.state.solver.BVS(
            "retval_{}".format(self.display_name), self.arch.bits
        )
