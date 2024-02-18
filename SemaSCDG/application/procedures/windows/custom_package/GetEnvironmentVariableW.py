from .GetEnvironmentVariableA import GetEnvironmentVariableA
import logging

import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class GetEnvironmentVariableW(GetEnvironmentVariableA):
    def get_str(self, lpName, size):
        if not self.state.has_plugin("plugin_env_var"):
            lw.warning("The procedure GetEnvironmentVariableW is using the plugin plugin_env_var which is not activated")
        name = self.state.mem[lpName].wstring.concrete
        if hasattr(name, "decode"):
            name = name.decode("utf-16-le")
        if self.state.has_plugin("plugin_env_var") and name in self.state.plugin_env_var.env_var:
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
            if self.state.has_plugin("plugin_env_var") : 
                self.state.plugin_env_var.env_var[name] = None
        if self.state.has_plugin("plugin_env_var") : 
            self.state.plugin_env_var.env_var_requested[name] = ret
        return ret
