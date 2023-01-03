import angr
import time as timer


class gettimeofday(angr.SimProcedure):
    def run(self, tv, tz):
        if self.state.solver.is_true(tv == 0):
            return -1

        if angr.options.USE_SYSTEM_TIMES in self.state.options:
            flt = timer.time()
            result = {"tv_sec": int(flt), "tv_usec": int(flt * 1000000)}
        else:
            result = {
                "tv_sec": self.state.solver.BVS(
                    "tv_sec", self.arch.bits, key=("api", "gettimeofday", "tv_sec")
                ),
                "tv_usec": self.state.solver.BVS(
                    "tv_usec", self.arch.bits, key=("api", "gettimeofday", "tv_usec")
                ),
            }

        self.state.mem[tv].struct.timeval = result
        return 0
