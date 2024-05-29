import angr
import logging

import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])

class OutputDebugStringW(angr.SimProcedure):
    NO_RET = True
    def run(self, lpOutputString):
        # Read the null-terminated string from memory
        output_string = self.state.mem[lpOutputString].wstring.concrete

        # Print the string to the console (or a log file, etc.)
        lw.debug("[DEBUG] " + output_string)

        # Return 0 (not a meaningful return value)
