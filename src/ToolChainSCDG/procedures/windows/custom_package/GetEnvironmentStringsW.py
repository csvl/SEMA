import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class GetEnvironmentStringsW(angr.SimProcedure):
    def run(self):
        return self.state.plugin_env_var.env_block
