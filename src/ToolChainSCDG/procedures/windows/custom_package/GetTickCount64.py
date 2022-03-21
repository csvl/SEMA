import logging
import time as timer
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class GetTickCount64(angr.SimProcedure):
    KEY = ("sim_time", "GetTickCount")

    def run(self):
        if angr.options.USE_SYSTEM_TIMES in self.state.options:
            return int(timer.perf_counter() * 1000) + 12345
        else:
            return self.state.solver.BVS(
                "retval_{}".format(self.display_name), self.arch.bits
            )
