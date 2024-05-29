import logging
import angr

import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])

# TODO: default behaviour if no plugin registered
class GetEnvironmentStrings(angr.SimProcedure):
    def run(self):
        if not self.state.has_plugin("plugin_env_var"):
            lw.warning("The procedure GetEnvironmentStrings is using the plugin plugin_env_var which is not activated")
        else :
            return self.state.plugin_env_var.env_block
