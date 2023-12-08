import logging
import angr

import configparser

config = configparser.ConfigParser()
config.read('config.ini')
lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(config['SCDG_arg'].get('log_level'))


class ReadFile(angr.SimProcedure):
    def run(
        self, hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped
    ):

        self.state.project
        simfd = self.state.posix.get_fd(hFile)
        if simfd is None:
            lw.warning("ReadFile: could not find fd")
            return 1
        bytes_read = simfd.read(
            lpBuffer, nNumberOfBytesToRead, endness=self.arch.memory_endness
        )
        self.state.memory.store(
            lpNumberOfBytesRead, bytes_read, endness=self.arch.memory_endness
        )
        return 1
        # return self.state.solver.BVS("retval_{}".format(self.display_name),self.arch.bits)
