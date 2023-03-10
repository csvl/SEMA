import angr
import claripy

class RepMovsbHook(angr.SimProcedure):
    NO_RET = True
    def __init__(self, plength=0, project=None, cc=None, prototype=None, symbolic_return=None, returns=None, is_syscall=False, is_stub=False, num_args=None, display_name=None, library_name=None, is_function=None, **kwargs):
        super().__init__(project, cc, prototype, symbolic_return, returns, is_syscall, is_stub, num_args, display_name, library_name, is_function, **kwargs)
        self.plength=plength
        
    def run(self):
        ecx = self.state.solver.eval(self.state.regs.ecx)
        esi = self.state.solver.eval(self.state.regs.esi)
        edi = self.state.solver.eval(self.state.regs.edi)
        length = ecx
        self.state.regs.ecx = 0
        if self.state.globals["df"] == 0:
            self.state.memory.store(edi, self.state.memory.load(esi,length))
            self.state.regs.edi = self.state.regs.edi + length
            self.state.regs.esi = self.state.regs.esi + length
        if self.state.globals["df"] == 1:
            self.state.memory.store(edi+1-length, self.state.memory.load(esi+1-length,length))
            self.state.regs.edi = self.state.regs.edi - length
            self.state.regs.esi = self.state.regs.esi - length
        jumpkind = 'Ijk_NoHook' if self.plength == 0 else 'Ijk_Boring'
        print(self.plength)
        self.successors.add_successor(self.state, self.state.addr+self.plength, self.state.solver.true, jumpkind)
        #return   