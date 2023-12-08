import angr
import logging
import configparser

config = configparser.ConfigParser()
config.read('config.ini')
lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(config['SCDG_arg'].get('log_level'))

class getsockname(angr.SimProcedure):

    def run(self, s, name, namelen):
        return 0x0
