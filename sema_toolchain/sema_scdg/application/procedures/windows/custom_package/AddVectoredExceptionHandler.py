import os
import sys


import logging
import angr
import os

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)


class AddVectoredExceptionHandler(angr.SimProcedure):
    def run(
        self,
        First,
        Handler
    ):
        self.state.globals['handler'] = Handler
        self.state.globals['jump'] = 0x4025b3 # TODO
        return 0x1
