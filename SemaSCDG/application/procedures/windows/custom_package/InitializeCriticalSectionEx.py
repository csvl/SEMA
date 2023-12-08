import logging
import angr
import configparser

config = configparser.ConfigParser()
config.read('config.ini')
lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(config['SCDG_arg'].get('log_level'))


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
