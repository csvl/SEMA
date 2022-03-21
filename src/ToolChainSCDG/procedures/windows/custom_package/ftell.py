import logging
import angr
from cle.backends.externs.simdata.io_file import io_file_data_for_arch

lw = logging.getLogger("CustomSimProcedureWindows")


class ftell(angr.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, file_ptr):
        fd_offset = io_file_data_for_arch(self.state.arch)["fd"]
        fd = self.state.mem[file_ptr + fd_offset].int.resolved
        simfd = self.state.posix.get_fd(fd)
        # import pdb; pdb.set_trace()
        if simfd is None:
            return -1
        pos = simfd.tell()
        # import pdb; pdb.set_trace()
        if pos is None:
            return 2
        return pos
