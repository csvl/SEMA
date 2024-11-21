import os
import sys


import angr
import logging
import os

try: 
    lw = logging.getLogger("CustomSimProcedureLinux")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)

class readdir(angr.SimProcedure):
    # pylint: disable=arguments-differ
    def run(self,dirp):
        lw.debug(self.cc)
        return 0
