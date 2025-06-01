import os
import sys
import logging
import angr
import claripy

try:
    lw = logging.getLogger("CustomSimProcedureLinux")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)


class EVP_CipherFinal_ex(angr.SimProcedure):
    def run(self, ctx, outbuf, outlen):
        # return 1 for success and 0 for failure
        lw.debug("EVP_CipherFinal_ex called")
        self.state.memory.store(outbuf, 0)
        self.state.memory.store(outlen, 0)
        ret_val = self.state.solver.BVS("retval_{}".format(self.display_name), self.state.arch.bits)
        self.state.solver.add(claripy.Or(ret_val == 0, ret_val == 1))
        return ret_val