import os
import sys
import logging
import angr
import claripy
from angr.procedures.libc.system import system

try:
    lw = logging.getLogger("CustomSimProcedureLinux")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)


class EVP_CipherUpdate(angr.SimProcedure):
    def run(self, ctx, outbuf, outlen, inbuf, inlen):
        # return 1 for success and 0 for failure
        lw.debug("EVP_CipherUpdate.run")


        val = self.state.solver.eval(inlen)
        lw.debug(val)

        self.state.memory.store(outlen,val)

        ret_val = self.state.solver.BVS("retval_{}".format(self.display_name), self.state.arch.bits)
        self.state.solver.add(claripy.Or(ret_val == 0, ret_val == 1))
        return ret_val