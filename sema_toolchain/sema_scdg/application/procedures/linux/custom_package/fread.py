import os
import random
import sys
import logging
import angr
import claripy
from cle.backends.externs.simdata.io_file import io_file_data_for_arch

try:
    lw = logging.getLogger("CustomSimProcedureLinux")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)

class fread(angr.SimProcedure):
    #code from : https://github.com/angr/angr/blob/master/angr/procedures/libc/fread.py
    def run(self, buffer, size, count, stream):
        lw.debug("fread")
        #real implementation
        # lw.debug(self.state.solver.eval(size*count))
        # fd_offset = io_file_data_for_arch(self.state.arch)["fd"]
        # fd = self.state.mem[stream + fd_offset :].int.resolved
        # simfd = self.state.posix.get_fd(fd)
        # if simfd is None:
        #     lw.debug("fread failed")
        #     return -1
        #
        # ret = simfd.read(buffer, size * count)
        # lw.debug(self.state.solver.eval(ret))
        #return claripy.If(claripy.Or(size == 0, count == 0), 0, ret // size)

        #but because empty file -> problem -> alway return 0
        return random.randint(0,5)