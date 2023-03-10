# 85 db <-> 0x0040132e

import angr

class MagicRATSSE3Hook(angr.SimProcedure):
    NO_RET = True
    def __init__(self, plength=0, project=None, cc=None, prototype=None, symbolic_return=None, returns=None, is_syscall=False, is_stub=False, num_args=None, display_name=None, library_name=None, is_function=None, **kwargs):
        super().__init__(project, cc, prototype, symbolic_return, returns, is_syscall, is_stub, num_args, display_name, library_name, is_function, **kwargs)
        self.plength=plength
        
    def run(self):
        self.state.regs.r9d = 0 # set TEST r9d, r9d to true
        self.state.regs.r9  = 0 
        ret_addr = self.state.stack_pop()
        self.state.regs.esp += 4 * 6
        new_state = self.state.copy()
        new_state.stack_push(ret_addr)
        self.successors.add_successor(new_state, 0xf23270, new_state.solver.true, 'Ijk_Boring')
        self.returns = False
        #self.state.inspect.skip_jump = True
        # jumpkind = 'Ijk_NoHook' if self.plength == 0 else 'Ijk_Boring'
        # print(self.plength)
        # self.successors.add_successor(self.state, self.state.addr+self.plength, self.state.solver.true, jumpkind)
        #return   