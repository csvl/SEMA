import os
import sys


import angr
import claripy

class WannacryHook_cls_100071f8(angr.SimProcedure):
    NO_RET = True
    def __init__(self, plength=0, project=None, cc=None, prototype=None, symbolic_return=None, returns=None, is_syscall=False, is_stub=False, num_args=None, display_name=None, library_name=None, is_function=None, **kwargs):
        super().__init__(project, cc, prototype, symbolic_return, returns, is_syscall, is_stub, num_args, display_name, library_name, is_function, **kwargs)
        self.plength=plength

    def run(self,arg1):
        print("cls_100071f8 skip")
        #skip because corrupted ret addr
        #100057e3
        jumpkind = 'Ijk_NoHook' if self.plength == 0 else 'Ijk_Boring'
        self.successors.add_successor(self.state, self.state.addr+self.plength, self.state.solver.true, jumpkind)

        ret_val = self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
        self.state.solver.add(claripy.Or(ret_val == 0, ret_val == 1))
        return 1

