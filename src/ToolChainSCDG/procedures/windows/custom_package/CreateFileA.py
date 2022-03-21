import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class CreateFileA(angr.SimProcedure):
    def decodeString(self, ptr):
        filename = self.state.mem[ptr].string.concrete
        if hasattr(filename, "decode"):
            try:
                filename = filename.decode("utf-8")
            except UnicodeDecodeError as e:  # chris: TODO check
                # filename= filename.decode('utf-8', errors='surrogateescape')
                filename = filename.decode("utf-8", errors="ignore")
                # filename = filename.decode("ascii")
        return filename

    def run(
        self,
        lpFilename,
        dwDesiredAccess,
        dwShareMode,
        lpSecurituAttributes,
        dwCreationDisposition,
        dwFlagsAndAttributes,
        hTemplateFile,
    ):

        self.state.project
        # import pdb; pdb.set_trace()
        name = self.decodeString(lpFilename)
        lw.info(
            "CreateFileA: {}  asks to create file {}".format(self.display_name, name)
        )
        access = self.state.solver.eval(dwDesiredAccess)
        access & (1 << 31) or (access & (1 << 16))
        access & (1 << 30)
        access & (1 << 29)
        access & (1 << 28)

        """if (read & write) or allPerm :
            flag = 2
        elif write :
            flag = 1
        elif write ="""

        fd = self.state.posix.open(name, self.state.solver.BVV(2, self.arch.bits))
        # import pdb; pdb.set_trace()
        if fd is None:
            return self.state.solver.BVS(
                "retval_{}".format(self.display_name), self.arch.bits
            )
        return fd
