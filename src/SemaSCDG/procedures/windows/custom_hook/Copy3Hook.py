import angr

class Copy3Hook(angr.SimProcedure):
    NO_RET = True
    def __init__(self, plength=0, project=None, cc=None, prototype=None, symbolic_return=None, returns=None, is_syscall=False, is_stub=False, num_args=None, display_name=None, library_name=None, is_function=None, **kwargs):
        super().__init__(project, cc, prototype, symbolic_return, returns, is_syscall, is_stub, num_args, display_name, library_name, is_function, **kwargs)
        self.plength=plength
        
    def run(self):
        x = self.state.stack_pop()
        y = self.state.stack_pop()
        z = self.state.stack_pop()
        w = self.state.stack_pop()  
        self.state.stack_push(w)
        self.state.stack_push(z)
        self.state.stack_push(y)
        self.state.stack_push(x)
        self.state.memory.store(y, self.state.memory.load(z, w))
        jumpkind = 'Ijk_NoHook' if self.plength == 0 else 'Ijk_Boring'
        self.successors.add_successor(self.state, self.state.addr+self.plength, self.state.solver.true, jumpkind)
        #return
