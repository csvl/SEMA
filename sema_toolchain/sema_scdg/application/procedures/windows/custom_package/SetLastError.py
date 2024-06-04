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


class SetLastError(angr.SimProcedure):
    def run(self, dwErrcode):
        if not self.state.has_plugin("plugin_env_var"):
            lw.warning("The procedure SetLastError is using the plugin plugin_env_var which is not activated")
        else :
            self.state.plugin_env_var.last_error = dwErrcode
            # self.state.memory.load(self.state.regs.esp, 4  , endness= self.arch.memory_endness)
        return
