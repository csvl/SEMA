import logging
import angr
import configparser

config = configparser.ConfigParser()
config.read('config.ini')
lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(config['SCDG_arg'].get('log_level'))


class NtReadVirtualMemory(angr.SimProcedure):
    def run(
        self,
        ProcessHandle,
        BaseAddress,
        Buffer,
        NumberOfBytesToRead,
        NumberOfBytesReaded
    ):
        size = self.state.solver.eval(NumberOfBytesToRead)
        self.state.memory.store(Buffer, self.state.memory.load(BaseAddress,size))
        return 0x0
