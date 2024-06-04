import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
import angr

# class _set_app_type(angr.SimProcedure):
#     def run(self,type):
#         # return a pointer to the array of FILE descriptors
#         # self.state.posix.fd
#         return
