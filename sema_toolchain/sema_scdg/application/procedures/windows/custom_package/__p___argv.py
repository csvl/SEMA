import os
import sys
import logging
import angr

import os

import claripy

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ.get("LOG_LEVEL", "INFO"))
except Exception as e:
    print(e)


class __p___argv(angr.SimProcedure):
    def run(self, ):
        lw.debug("enter __p___argv")
        argv = self.state.posix.argv
        return argv
