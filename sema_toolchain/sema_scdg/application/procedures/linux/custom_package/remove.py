import os
import sys

import angr
import logging

try:
    lw = logging.getLogger("CustomSimProcedureLinux")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)

class remove(angr.SimProcedure):
    def run(self, name):
        #delet the <name> file.
        return 0
