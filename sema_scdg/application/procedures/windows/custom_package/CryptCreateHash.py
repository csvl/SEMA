import logging
import angr
import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


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
