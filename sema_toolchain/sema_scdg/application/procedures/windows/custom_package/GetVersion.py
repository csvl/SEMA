import os
import sys


import angr
import logging
import os

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)

# class GetVersion(angr.SimProcedure):
#     def run(self):
#         version = "9.0.0.1103"
#         return 1 # TODO
