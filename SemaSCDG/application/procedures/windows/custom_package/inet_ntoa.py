import angr
import logging
import configparser

config = configparser.ConfigParser()
config.read('config.ini')
import configparser

config = configparser.ConfigParser()
config.read('config.ini')
lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(config['SCDG_arg'].get('log_level'))
lw.setLevel(config['SCDG_arg'].get('log_level'))

class inet_ntoa(angr.SimProcedure):

    def run(self, addr):
        self.state.memory.store(0x666666,"192.168.1.1")
        return 0x666666
