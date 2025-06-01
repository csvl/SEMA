import os
import sys


import angr

class __p___argc(angr.SimProcedure):
    def run(self):
        # The __argc global variable is a count of the number of command-line arguments passed to the program.
        # https://learn.microsoft.com/en-us/cpp/c-runtime-library/argc-argv-wargv?view=msvc-170
        argc = self.state.heap.malloc(4)
        self.state.memory.store(argc, self.state.solver.BVS("retval_{}".format(self.display_name), 32))
        return argc
