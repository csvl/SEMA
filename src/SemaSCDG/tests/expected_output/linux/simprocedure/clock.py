import angr
import time as timer


class clock(angr.SimProcedure):
    def run(self):
        n_clock = int(timer.clock() * 1000)
        return n_clock
