import logging
import angr
import claripy
lw = logging.getLogger("CustomSimProcedureWindows")


class RtlMoveMemory(angr.SimProcedure):
    def run(
        self, Destination, Source, Length
    ):
        Destination = self.state.solver.eval(Destination)
        Source = self.state.solver.eval(Source)
        Length = self.state.solver.eval(Length)
        self.state.memory.store(Destination, self.state.memory.load(Destination, Length))
        return 0x0
