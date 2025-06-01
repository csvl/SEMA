import os
import sys


import angr
import claripy

class WannacryHook4(angr.SimProcedure):
    NO_RET = True
    def __init__(self, plength=0, project=None, cc=None, prototype=None, symbolic_return=None, returns=None, is_syscall=False, is_stub=False, num_args=None, display_name=None, library_name=None, is_function=None, **kwargs):
        super().__init__(project, cc, prototype, symbolic_return, returns, is_syscall, is_stub, num_args, display_name, library_name, is_function, **kwargs)
        self.plength=plength

    def run(self, param_1, param_2):
        #FUN_0040752

        #code generate by IA (chatgpt) with small modification on the inline_call

        arch_bits = self.state.arch.bits  # typically 32
        # Set param_1[1] = 0xffffffff
        self.state.memory.store(param_1 + 4, self.state.solver.BVV(0xffffffff, arch_bits))
        # Set param_1[0x4d] = 0xffffffff
        self.state.memory.store(param_1 + (0x4d * 4), self.state.solver.BVV(0xffffffff, arch_bits))
        # Set *param_1 = 0
        self.state.memory.store(param_1, self.state.solver.BVV(0, arch_bits))
        # Set param_1[0x4e] = 0
        self.state.memory.store(param_1 + (0x4e * 4), self.state.solver.BVV(0, arch_bits))
        # Set param_1[0x4f] = 0
        self.state.memory.store(param_1 + (0x4f * 4), self.state.solver.BVV(0, arch_bits))

        # If param_2 is not NULL
        if not self.state.solver.is_true(param_2 == 0):
            # Call strlen on param_2 to determine its length.
            strlen_sp = self.inline_call(angr.SIM_PROCEDURES['libc']['strlen'], param_2)
            sVar1 = strlen_sp.ret_expr

            # Allocate sVar1 + 1 bytes using operator_new.
            new_size = sVar1 + 1
            op_new_sp = self.inline_call(NewInt, new_size)
            _Dest = op_new_sp.ret_expr

            # Store the allocated pointer in param_1[0x4e]
            self.state.memory.store(param_1 + (0x4e * 4), _Dest)

            # Copy the string from param_2 to _Dest.
            self.inline_call(angr.SIM_PROCEDURES['libc']['strcpy'], _Dest, param_2)
        print(param_1)

        jumpkind = 'Ijk_NoHook' if self.plength == 0 else 'Ijk_Boring'
        self.successors.add_successor(self.state, self.state.addr+self.plength, self.state.solver.true, jumpkind)

        return param_1

class NewInt(angr.SimProcedure):

    def run(
            self,
            uint,
    ):
        if uint.symbolic:
            return self.state.heap._malloc(0x42)
        malloced = self.state.heap._malloc(uint)
        for i in range(self.state.solver.eval(uint)):
            self.state.memory.store(malloced + i, 0, size=1)
        print(malloced)
        return malloced

