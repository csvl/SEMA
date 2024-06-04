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


class SetUnhandledExceptionFilter(angr.SimProcedure):
    def run(
        self,
        lpTopLevelExceptionFilter
    ):
        self.state.globals['handler'] = lpTopLevelExceptionFilter
        self.state.globals['jump'] = 0x402635
        return 0x1
