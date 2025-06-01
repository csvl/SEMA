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


class WriteFile(angr.SimProcedure):
    def run(
        self,
        hFile,
        lpBuffer,
        nNumberOfBytesToWrite,
        lpNumberOfBytesWritten,
        lpOverlapped,
    ):

        if hFile.symbolic:
            lw.debug("symbolic hfile, skipping symbolic write")
            return self.state.solver.BVS(
                "retval_{}".format(self.display_name), self.arch.bits
            )

        simfd = self.state.posix.get_fd(hFile)

        if not simfd:
            lw.debug("WriteFile: could not find fd")
            return self.state.solver.BVS(
                "retval_{}".format(self.display_name), self.arch.bits
            )
        bytes_written = simfd.write(lpBuffer, nNumberOfBytesToWrite)
        lw.debug("bytes_written: {}".format(bytes_written))
        self.state.memory.store(
            lpNumberOfBytesWritten, bytes_written, endness=self.arch.memory_endness
        )
        lw.debug(self.state.globals["files"])
        lw.debug(simfd)
        lw.debug(self.state.solver.eval(hFile))
        if self.state.solver.eval(hFile) in self.state.globals["files"]:
            realfd = self.state.globals["files"][self.state.solver.eval(hFile)]
            lw.debug(realfd)
            if realfd is not None:
                with open(realfd, "ab") as fd:# TODO fix
                    content = self.state.solver.eval(self.state.memory.load(lpBuffer,nNumberOfBytesToWrite),cast_to=bytes)
                    lw.debug(content)
                    fd.write(content)
        return 1
