import logging
import angr
import configparser

config = configparser.ConfigParser()
config.read('config.ini')
lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(config['SCDG_arg'].get('log_level'))


class LookupPrivilegeValueA(angr.SimProcedure):
    def run(
        self,
        lpSystemName,
        lpName,
        lpLuid
    ):
        return 0x1
