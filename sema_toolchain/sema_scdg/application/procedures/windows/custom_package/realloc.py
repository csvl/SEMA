import os
import sys


import angr

######################################
# realloc
######################################

import logging

import os

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)

class realloc(angr.SimProcedure):
    #pylint:disable=arguments-differ
    def run(self, ptr, size):
        return self.state.heap._realloc(ptr, size)
