import angr
import claripy
import logging
import os

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ.get("LOG_LEVEL", "INFO"))
except Exception as e:
    print(e)

class CryptEncrypt(angr.SimProcedure):
    def run(
        self,
        hKey,
        hHash,
        Final,
        dwFlags,
        pbData,
        pdwDataLen,
        dwBufLen
    ):
        lw.debug("CryptEncrypt called")
        try:
            str_data = self.state.mem[pbData].string.concrete
            lw.debug("data to encrypt : {}".format(str_data))
        except:
            pass
        retval = self.state.solver.BVS(
            "retval_{}".format(self.display_name), self.arch.bits
        )
        self.state.solver.add(claripy.Or(retval == 0, retval == 1))
        return retval