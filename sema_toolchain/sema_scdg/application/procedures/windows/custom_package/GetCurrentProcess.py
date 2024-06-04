import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
# import angr
# import claripy

# class GetCurrentProcess(angr.SimProcedure):
#     def run(self):
#         return self.state.solver.BVV(0xffffffff, self.state.arch.bits)
