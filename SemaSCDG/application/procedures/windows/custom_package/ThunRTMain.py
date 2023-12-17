import logging
import angr

import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class ThunRTMain(angr.SimProcedure):
    def run(self,address_VB):
        import pdb
        pdb.set_trace()
        return 0x0
