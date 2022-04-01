from codecs import ignore_errors
import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class GetEnvironmentVariableA(angr.SimProcedure):
    """
    https://docs.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-getenvironmentvariablea
    """

    def get_str(self, lpName, size):
        name = self.state.mem[lpName].string.concrete
        if hasattr(name, "decode"):
            try:
                name = name.decode("utf-8")
            except:
                name = name.decode("utf-8", errors="ignore")
        name = name.upper()
        if name in self.state.plugin_env_var.env_var:
            ret = self.state.plugin_env_var.env_var[name][:size]
            # lw.warning(name + " " + str(size) + " " + ret)
            try:  # TODO investigate why needed with explorer
                if ret[-1] != "\0":
                    ret[-1] = "\0"
            except IndexError:
                lw.warning("IndexError - GetEnvironmentVariableA")
                ret = "\0"
            if hasattr(ret, "encode"):
                ret = ret.encode("utf-8")
        else:
            ret = None
        return ret

    def run(self, lpName, lpBuffer, nSize):
        if lpName.symbolic or lpBuffer.symbolic or nSize.symbolic:
            return self.state.solver.BVS(
                "retval_{}".format(self.display_name), self.arch.bits
            )

        size = self.state.mem[nSize].int.concrete
        ret_len = size

        var = self.get_str(lpName, size)
        # import pdb; pdb.set_trace()
        if var:
            new_str = self.state.solver.BVV(var)
            ret_len = len(var)

            self.state.memory.store(
                lpBuffer, new_str
            )  # ,endness=self.arch.memory_endness)
        else:
            for i in range(size):
                c = self.state.solver.BVS(
                    "c{}_env_var_{}".format(i, self.display_name), 8
                )
                self.state.memory.store(lpBuffer + i, c)
                return self.state.solver.BVS(
                    "retval_{}".format(self.display_name), self.arch.bits
                )
        return ret_len
