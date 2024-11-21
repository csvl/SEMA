import os
import sys


import logging
import angr

import os

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)


class ThunRTMain(angr.SimProcedure):
    def run(self,address_VB):
        import pdb
        pdb.set_trace()
        return 0x0
