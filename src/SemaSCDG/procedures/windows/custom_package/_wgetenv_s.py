import angr
import logging

lw = logging.getLogger("CustomSimProcedureWindows")

class _wgetenv_s(angr.SimProcedure):
    def get_str(self, lpName):
        name = self.state.mem[lpName].wstring.concrete
        # if hasattr(name, "decode"):
        #     name = name.decode("utf-16-le")
        name = name.upper()
        lw.info(name)
        name = str(name.encode("utf-8")).replace("b'","").replace("'","")
        lw.info(name)
        lw.info(self.state.plugin_env_var.wenv_var.keys())
        if name in self.state.plugin_env_var.wenv_var.keys() and self.state.plugin_env_var.wenv_var[name] != None:
            lw.info("Swag")
            ret = self.state.plugin_env_var.wenv_var[name].decode("utf-16-le")
            lw.info(ret)
            # lw.warning(name + " " + str(size) + " " + ret)
            try:  # TODO investigate why needed with explorer
                if ret[-1] != "\0":
                    ret += "\0"
            except IndexError:
                lw.warning("IndexError - GetEnvironmentVariableA")
                ret = "\0"
            if hasattr(ret, "encode"):
                ret = ret.encode("utf-16-le")
        else:
            ret =  None #"None"
            self.state.plugin_env_var.wenv_var[name] = None
        lw.info(ret)
        self.state.plugin_env_var.wenv_var_requested[name] = ret
        return ret


    def run(self, pReturnValue, buffer, numberOfElements, varname):
        if varname.symbolic:
            lw.info("varname is symb")
            return self.state.solver.BVS(
                "retval_{}".format(self.display_name), self.arch.bits
            )
        # Get the environment variable value
        env_value = self.get_str(varname)
        
        lw.info(env_value)

        # If the environment variable is not defined, set the return value to EINVAL
        if env_value is None:
            return self.state.solver.BVS(
                    "retval_{}".format(self.display_name), self.arch.bits
            )

        # If the environment variable is defined, copy its value to the buffer
        buf_size = min(len(env_value), self.state.solver.eval(numberOfElements) - 1)
        self.state.memory.store(buffer, env_value[:buf_size] + b"\0")

        # Set the return value to zero and update pReturnValue with the number of characters copied
        self.state.memory.store(pReturnValue, buf_size, self.state.arch.bits)
        return 0x0 #self.state.solver.BVV(0, self.state.arch.bits)
