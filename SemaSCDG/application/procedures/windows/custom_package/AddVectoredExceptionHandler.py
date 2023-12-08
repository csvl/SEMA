import logging
import angr
import configparser

config = configparser.ConfigParser()
config.read('config.ini')
lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(config['SCDG_arg'].get('log_level'))


class AddVectoredExceptionHandler(angr.SimProcedure):
    def run(
        self,
        First,
        Handler
    ):
        self.state.globals['handler'] = Handler
        self.state.globals['jump'] = 0x4025b3 # TODO
        return 0x1
