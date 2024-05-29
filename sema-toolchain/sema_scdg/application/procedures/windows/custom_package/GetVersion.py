import angr
import logging
import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])

# class GetVersion(angr.SimProcedure):
#     def run(self):
#         version = "9.0.0.1103"
#         return 1 # TODO
