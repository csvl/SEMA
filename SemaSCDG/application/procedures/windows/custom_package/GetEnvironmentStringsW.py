import logging
import angr

import configparser

config = configparser.ConfigParser()
config.read('config.ini')
lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(config['SCDG_arg'].get('log_level'))


class GetEnvironmentStringsW(angr.SimProcedure):
    def run(self):
        return self.state.plugin_env_var.env_blockw
