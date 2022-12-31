import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class ReadFile(angr.SimProcedure):
    def run(
        self, hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped
    ):

        self.state.project
        simfd = self.state.posix.get_fd(hFile)
        if simfd is None:
            lw.info("ReadFile: could not find fd")
            return self.state.solver.BVS(
                "retval_{}".format(self.display_name), self.arch.bits
            )
        bytes_read = simfd.read(
            lpBuffer, nNumberOfBytesToRead, endness=self.arch.memory_endness
        )
        lw.info(bytes_read)
        self.state.memory.store(
            lpNumberOfBytesRead, bytes_read, endness=self.arch.memory_endness
        )
        return 1
        # return self.state.solver.BVS("retval_{}".format(self.display_name),self.arch.bits)
