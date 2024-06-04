import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
import logging
import angr
import claripy
import os

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)


class RtlMoveMemory(angr.SimProcedure):
    def run(
        self, Destination, Source, Length
    ):
        Destination = self.state.solver.eval(Destination)
        Source = self.state.solver.eval(Source)
        Length = self.state.solver.eval(Length)
        self.state.memory.store(Destination, self.state.memory.load(Destination, Length))
        return 0x0
