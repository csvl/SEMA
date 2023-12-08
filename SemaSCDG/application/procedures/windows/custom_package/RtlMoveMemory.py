import logging
import angr
import claripy
import configparser

config = configparser.ConfigParser()
config.read('config.ini')
lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(config['SCDG_arg'].get('log_level'))


class RtlMoveMemory(angr.SimProcedure):
    def run(
        self, Destination, Source, Length
    ):
        Destination = self.state.solver.eval(Destination)
        Source = self.state.solver.eval(Source)
        Length = self.state.solver.eval(Length)
        self.state.memory.store(Destination, self.state.memory.load(Destination, Length))
        return 0x0
