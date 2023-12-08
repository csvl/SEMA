import logging
import angr
import hashlib
import configparser

config = configparser.ConfigParser()
config.read('config.ini')
lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(config['SCDG_arg'].get('log_level'))


class CryptHashData(angr.SimProcedure):
    def run(
        self,
        hHash,
        pbData,
        dwDataLen,
        dwFlags
    ):
        if self.state.globals["crypt_algo"] == 0x8003:
            string = self.state.memory.load(pbData,dwDataLen)
            s_bytes = self.state.solver.eval(string, cast_to=bytes) 
            result = hashlib.md5(s_bytes)
            self.state.globals["crypt_result"] = result.digest()
        return 0x1
