import os
import sys
import logging
import angr

try:
    lw = logging.getLogger("CustomSimProcedureLinux")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)


class rewind(angr.SimProcedure):
    def run(self,fd):
        # rewind fd to it original position
        concrete_fd = self.state.posix.get_fd(fd)
        if concrete_fd is None:
            return -1
        concrete_fd.seek(0)
        return 0