import os
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


class fwrite(angr.SimProcedure):
    #code from =  https://github.com/angr/angr/blob/master/angr/procedures/libc/fwrite.py
    # pylint:disable=arguments-differ
    def run(self, buffer, size, count, stream):
        # buffer 	- 	pointer to the first object in the array to be written
        # size 	- 	size of each object
        # count 	- 	the number of the objects to be written
        # stream 	- 	pointer to the output stream
        # file are empty so no data to read/write
        lw.debug("fwrite")
        # ret_val = self.state.solver.BVS('ret_val', self.state.arch.bits)
        # self.state.solver.add(claripy.Or(ret_val == 0, ret_val == 2))
        # return ret_val
        lw.debug(count)
        lw.debug(self.state.solver.eval(count))
        fd_offset = io_file_data_for_arch(self.state.arch)["fd"]
        fileno = self.state.mem[stream + fd_offset :].int.resolved
        simfd = self.state.posix.get_fd(fileno)
        if simfd is None:
            return -1
        return simfd.write(buffer, size * count)

fwrite_unlocked = fwrite