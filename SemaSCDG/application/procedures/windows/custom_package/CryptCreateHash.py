import logging
import angr
import configparser

config = configparser.ConfigParser()
config.read('config.ini')
lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(config['SCDG_arg'].get('log_level'))


class CryptCreateHash(angr.SimProcedure):
    def run(
        self,
        hProv,
        Algid,
        hKey,
        dwFlags,
        phHash
    ):
        self.state.globals["crypt_algo"] = 0x8003
        return 0x1
