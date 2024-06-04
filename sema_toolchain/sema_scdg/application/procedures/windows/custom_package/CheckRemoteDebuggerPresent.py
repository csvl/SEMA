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


class CheckRemoteDebuggerPresent(angr.SimProcedure):
    def run(
        self,
        hProcess,
        pbDebuggerPresent
    ):
        dbg = self.state.solver.BVV(0, self.arch.bits)
        self.state.memory.store(pbDebuggerPresent, dbg)
        return 0x1
