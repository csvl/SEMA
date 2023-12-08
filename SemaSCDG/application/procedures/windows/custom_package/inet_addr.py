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

class inet_addr(angr.SimProcedure):

    def run(self, cp):
        try:
            print(self.state.mem[cp].string.concrete)
        except:
            print(self.state.memory.load(cp,0x20))
        return 123456
