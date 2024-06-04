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


class InitializeCriticalSectionEx(angr.SimProcedure):
    def run(
        self,
        lpCriticalSection,
        dwSpinCount,
        Flags
    ):
        x = self.state.stack_pop()
        self.state.stack_pop()
        self.state.stack_pop()
        self.state.stack_pop()
        self.state.stack_push(x)
        return 0x1
