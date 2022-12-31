from .GetEnvironmentVariableA import GetEnvironmentVariableA
import logging

lw = logging.getLogger("CustomSimProcedureWindows")


class GetEnvironmentVariableW(GetEnvironmentVariableA):
    def get_str(self, lpName, size):
        name = self.state.mem[lpName].wstring.concrete
        if hasattr(name, "decode"):
            name = name.decode("utf-16-le")
        if name in self.state.plugin_env_var.env_var:
            ret = self.state.plugin_env_var.env_var[name][:size]
            try:  # TODO investigate why needed with explorer
                if ret[-1] != "\0":
                    ret[-1] = "\0"
            except IndexError:
                lw.warning("IndexError - GetEnvironmentVariableW")
                ret = "\0"
            if hasattr(ret, "encode"):
                ret = ret.encode("utf-16-le")
        else:
            ret = None
        return ret
