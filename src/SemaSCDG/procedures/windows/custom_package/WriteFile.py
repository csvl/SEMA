import logging
import angr

 
lw = logging.getLogger("CustomSimProcedureWindows")


class WriteFile(angr.SimProcedure):
    def run(
        self,
        hFile,
        lpBuffer,
        nNumberOfBytesToWrite,
        lpNumberOfBytesWritten,
        lpOverlapped,
    ):
        self.state.project
        simfd = self.state.posix.get_fd(hFile)
        if simfd is None:
            lw.info("WriteFile: could not find fd")
            return self.state.solver.BVS(
                "retval_{}".format(self.display_name), self.arch.bits
            )
        bytes_written = simfd.write(lpBuffer, nNumberOfBytesToWrite)
        self.state.memory.store(
            lpNumberOfBytesWritten, bytes_written, endness=self.arch.memory_endness
        )
        lw.info(self.state.globals["files"])
        lw.info(simfd)
        lw.info(self.state.solver.eval(hFile))
        if self.state.solver.eval(hFile) in self.state.globals["files"]:
            realfd = self.state.globals["files"][self.state.solver.eval(hFile)]
            lw.info(realfd)
            if realfd is not None:
                with open(realfd, "ab") as fd:# TODO fix
                    content = self.state.solver.eval(self.state.memory.load(lpBuffer,nNumberOfBytesToWrite),cast_to=bytes)
                    lw.info(content)
                    fd.write(content)
        return 1
