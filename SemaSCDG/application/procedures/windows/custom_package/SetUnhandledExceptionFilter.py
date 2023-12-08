import logging
import angr
import configparser

config = configparser.ConfigParser()
config.read('config.ini')
lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(config['SCDG_arg'].get('log_level'))


class SetUnhandledExceptionFilter(angr.SimProcedure):
    def run(
        self,
        lpTopLevelExceptionFilter
    ):
        self.state.globals['handler'] = lpTopLevelExceptionFilter
        self.state.globals['jump'] = 0x402635
        return 0x1
