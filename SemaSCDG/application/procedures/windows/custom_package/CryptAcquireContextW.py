import logging
import angr
import configparser

config = configparser.ConfigParser()
config.read('config.ini')
lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(config['SCDG_arg'].get('log_level'))


class CryptAcquireContextW(angr.SimProcedure):
    def run(
        self,
        phProv,
        szContainer,
        szProvider,
        dwProvType,
        dwFlags
    ):
        return 0x1
