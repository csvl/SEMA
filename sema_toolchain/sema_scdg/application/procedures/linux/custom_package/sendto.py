import os
import sys


import angr


class sendto(angr.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, fd, src, length, flags):  # pylint:disable=unused-argument
        simfd = self.state.posix.get_fd(fd)
        if simfd is None:
            return -1
        return simfd.write(src, length)  # if send succeeds
