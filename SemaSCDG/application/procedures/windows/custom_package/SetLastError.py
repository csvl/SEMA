import logging
import angr

import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class SetLastError(angr.SimProcedure):
    def run(self, dwErrcode):

        self.state.plugin_env_var.last_error = dwErrcode
        # self.state.memory.load(self.state.regs.esp, 4  , endness= self.arch.memory_endness)
        return
