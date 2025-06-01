import os
import sys


import angr
import claripy

class WannacryHook_add_to_file_list(angr.SimProcedure):
    NO_RET = True
    def __init__(self, plength=0, project=None, cc=None, prototype=None, symbolic_return=None, returns=None, is_syscall=False, is_stub=False, num_args=None, display_name=None, library_name=None, is_function=None, **kwargs):
        super().__init__(project, cc, prototype, symbolic_return, returns, is_syscall, is_stub, num_args, display_name, library_name, is_function, **kwargs)
        self.plength=plength

    def run(self,arg1,arg2,arg3,arg4):
        print("add_to_file_list skip")
        #skip because corrupted ret addr
        #0x10002625
        jumpkind = 'Ijk_NoHook' if self.plength == 0 else 'Ijk_Boring'
        self.successors.add_successor(self.state, self.state.addr+self.plength, self.state.solver.true, jumpkind)

        self.state.memory.store(arg2,self.state.solver.BVS("symbolic_list", self.arch.bits))

        return self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)

