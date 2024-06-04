import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
import angr
import logging

import os

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)

class OutputDebugStringW(angr.SimProcedure):
    NO_RET = True
    def run(self, lpOutputString):
        # Read the null-terminated string from memory
        output_string = self.state.mem[lpOutputString].wstring.concrete

        # Print the string to the console (or a log file, etc.)
        lw.debug("[DEBUG] " + output_string)

        # Return 0 (not a meaningful return value)
