import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
import logging
import angr
import hashlib
import os

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)


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
