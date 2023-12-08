import logging
import angr

import configparser

config = configparser.ConfigParser()
config.read('config.ini')
lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(config['SCDG_arg'].get('log_level'))


class ThunRTMain(angr.SimProcedure):
    def run(self,address_VB):
        import pdb
        pdb.set_trace()
        return 0x0
