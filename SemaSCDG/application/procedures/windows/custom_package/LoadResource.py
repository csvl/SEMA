import logging
import sys
import angr
import archinfo

import configparser

config = configparser.ConfigParser()
config.read('config.ini')
lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(config['SCDG_arg'].get('log_level'))

class LoadResource(angr.SimProcedure):
    def run(self, hModule, hResInfo):
        return hResInfo
           
        
