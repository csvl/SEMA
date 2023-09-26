import angr

class CPUIDHook(angr.SimProcedure):
    NO_RET = True
    def __init__(self, plength=0, project=None, cc=None, prototype=None, symbolic_return=None, returns=None, is_syscall=False, is_stub=False, num_args=None, display_name=None, library_name=None, is_function=None, **kwargs):
        super().__init__(project, cc, prototype, symbolic_return, returns, is_syscall, is_stub, num_args, display_name, library_name, is_function, **kwargs)
        self.plength=plength
        
    def run(self):
        eax = self.state.solver.eval(self.state.regs.rax)
        ecx = self.state.solver.eval(self.state.regs.rcx)
        if eax == 0:
            # Return the maximum value for basic functions
            self.state.regs.rax = 0x8000001F
        elif eax == 1:
            # Set ECX bit 26 (OSXSAVE) and bit 0 (SSE3) to enable AVX support
            self.state.regs.rcx |= 1 << 26
            self.state.regs.rcx |= 1 << 0
            # Set EDX bit 25 (SSE) and bit 26 (SSE2) to enable SSE and SSE2 support
            self.state.regs.rdx |= 1 << 25
            self.state.regs.rdx |= 1 << 26
        elif eax == 7 and ecx == 0:
            # Set EBX bit 5 (AVX2), ECX bit 16 (AVX512F), and ECX bit 9 (SSE4.2) to enable AVX2 and AVX-512 support
            # and SSE4.2 support
            self.state.regs.rbx |= 1 << 5
            self.state.regs.rcx |= 1 << 16
            self.state.regs.rcx |= 1 << 9
            # Set EDX bit 25 (SSE) and bit 26 (SSE2) to enable SSE and SSE2 support
            self.state.regs.rdx |= 1 << 25
            self.state.regs.rdx |= 1 << 26
        elif eax == 0x80000001:
            # Set EDX bit 28 (xsave), bit 26 (osxsave), and bit 0 (SSE3) to enable XSAVE and AVX support on 64-bit platforms
            self.state.regs.rdx |= 1 << 28
            self.state.regs.rdx |= 1 << 26
            self.state.regs.rdx |= 1 << 0
            # Set ECX bit 9 (SSE4.2) to enable SSE4.2 support
            self.state.regs.rcx |= 1 << 9
        else:
            raise angr.errors.SimSegfaultError("Invalid CPUID opcode")
        
        jumpkind = 'Ijk_NoHook' if self.plength == 0 else 'Ijk_Boring'
        print(self.plength)
        self.successors.add_successor(self.state, self.state.addr+self.plength, self.state.solver.true, jumpkind)
        #return 