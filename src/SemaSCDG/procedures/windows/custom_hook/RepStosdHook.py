import angr
import claripy

class RepStosdHook(angr.SimProcedure):
    NO_RET = True
    def __init__(self, plength=0, project=None, cc=None, prototype=None, symbolic_return=None, returns=None, is_syscall=False, is_stub=False, num_args=None, display_name=None, library_name=None, is_function=None, **kwargs):
        super().__init__(project, cc, prototype, symbolic_return, returns, is_syscall, is_stub, num_args, display_name, library_name, is_function, **kwargs)
        self.plength=plength
    
    def run(self):
        ecx = self.state.solver.eval(self.state.regs.ecx)
        length = ecx*4
        ptr = claripy.BVV(0x0,length*8)
        self.state.memory.store(self.state.regs.edi, ptr)
        self.state.regs.ecx = 0
        self.state.regs.edi = self.state.regs.edi + length
        jumpkind = 'Ijk_NoHook' if self.plength == 0 else 'Ijk_Boring'
        print(self.plength)
        self.successors.add_successor(self.state, self.state.addr+self.plength, self.state.solver.true, jumpkind)
        #return