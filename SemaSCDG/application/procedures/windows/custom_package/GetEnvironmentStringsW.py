import logging
import angr

import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class GetEnvironmentStringsW(angr.SimProcedure):
    def run(self):
        return self.state.plugin_env_var.env_blockw
