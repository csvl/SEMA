import angr
import logging
import configparser

config = configparser.ConfigParser()
config.read('config.ini')
lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(config['SCDG_arg'].get('log_level'))

# class GetVersion(angr.SimProcedure):
#     def run(self):
#         version = "9.0.0.1103"
#         return 1 # TODO
