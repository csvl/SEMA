import logging
import angr
import configparser

config = configparser.ConfigParser()
config.read('config.ini')
lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(config['SCDG_arg'].get('log_level'))


class NtUnmapViewOfSection(angr.SimProcedure):
    def run(
        self,
        ProcessHandle,
        BaseAddress
    ):
        return 0x0
