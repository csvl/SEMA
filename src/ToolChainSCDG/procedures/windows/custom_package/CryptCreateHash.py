import logging
import angr
lw = logging.getLogger("CustomSimProcedureWindows")


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
