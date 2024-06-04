import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
import logging
import angr

import os

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)


class GetEnvironmentStringsW(angr.SimProcedure):
    def run(self):
        if not self.state.has_plugin("plugin_env_var"):
            lw.warning("The procedure GetEnvironmentStringsW is using the plugin plugin_env_var which is not activated")
        else :
            return self.state.plugin_env_var.env_blockw
