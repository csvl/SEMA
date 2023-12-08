import logging
import angr
import configparser

config = configparser.ConfigParser()
config.read('config.ini')
lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(config['SCDG_arg'].get('log_level'))


class IsDebuggerPresent(angr.SimProcedure):
    def run(
        self
    ):
        return 0x0
