import logging
import time as timer
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class QueryPerformanceFrequency(angr.SimProcedure):
    def run(self, ptr):
        if angr.options.USE_SYSTEM_TIMES in self.state.options:
            val = int(timer.perf_counter() * 1000000) + 12345678
            # self.state.mem[ptr].qword = val
            addr = self.state.solver.eval(ptr)
            data = self.state.solver.BVV(val, self.arch.bits)
            self.state.memory.store(addr, data)
        else:
            # self.state.mem[ptr].qword = self.state.solver.BVS(
            #     "retval_{}".format(self.display_name), self.arch.bits
            # )
            addr = self.state.solver.eval(ptr)
            data = self.state.solver.BVS(
                "retval_{}".format(self.display_name), self.arch.bits
            )
            self.state.memory.store(addr, data)
        return 1
