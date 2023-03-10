import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class getenv(angr.SimProcedure):
    """
    https://docs.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-getenvironmentvariablea
    """
    def get_str(self, lpName):
        name = self.state.mem[lpName].string.concrete
        if hasattr(name, "decode"):
            name = name.decode("utf-8")
        name = name.upper()
        lw.info(name)
        if name in self.state.plugin_env_var.env_var.keys() and self.state.plugin_env_var.env_var[name] != None:
            lw.info("Swag")
            ret = self.state.plugin_env_var.env_var[name]
            lw.info(ret)
            # lw.warning(name + " " + str(size) + " " + ret)
            try:  # TODO investigate why needed with explorer
                if ret[-1] != "\0":
                    ret += "\0"
            except IndexError:
                lw.warning("IndexError - GetEnvironmentVariableA")
                ret = "\0"
            if hasattr(ret, "encode"):
                ret = ret.encode("utf-8")
        else:
            ret =  None #"None"
            self.state.plugin_env_var.env_var[name] = None
        lw.info(ret)
        self.state.plugin_env_var.env_var_requested[name] = ret
        return ret

    def run(self, lpName):
        if lpName.symbolic:
            return self.state.solver.BVS(
                "retval_{}".format(self.display_name), self.arch.bits
            )
        
        var = self.get_str(lpName)
        # import pdb; pdb.set_trace()
        if var:
            new_str = self.state.solver.BVV(var)
            ret_len = len(var)
            lpBuffer = self.state.heap._malloc(ret_len)
            self.state.memory.store(
                lpBuffer, new_str
            )  # ,endness=self.arch.memory_endness)
            return lpBuffer
        else:
            return self.state.solver.BVS(
                    "retval_{}".format(self.display_name), self.arch.bits
            )
            # self.state.memory.store(
            #     lpBuffer, new_str
            # )  # ,endness=self.arch.memory_endness)
        # else:
        #     for i in range(size):
        #         c = self.state.solver.BVS(
        #             "c{}_env_var_{}".format(i, self.display_name), 8
        #         )
        #         self.state.memory.store(lpBuffer + i, c)
        #         return self.state.solver.BVS(
        #             "retval_{}".format(self.display_name), self.arch.bits
        #         )