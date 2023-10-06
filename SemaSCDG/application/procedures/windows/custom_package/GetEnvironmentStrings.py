import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")

# TODO: default behaviour if no plugin registered
class GetEnvironmentStrings(angr.SimProcedure):
    def run(self):
        return self.state.plugin_env_var.env_block
