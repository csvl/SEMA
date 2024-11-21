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


class Handler(angr.SimProcedure):
    IS_FUNCTION = True

    def run(self):
        self.call(self.state.globals['handler'], (self.state.posix.argc, self.state.posix.argv, self.state.posix.environ), 'run_initializer')

    def run_initializer(self):
            self.jump(self.state.globals['jump'])
