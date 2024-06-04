import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
import angr

######################################
# free
######################################
class free(angr.SimProcedure):
    # pylint:disable=arguments-differ,unused-argument

    def run(self, ptr):
        self.state.heap._free(ptr)
