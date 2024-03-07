# 85 db <-> 0x0040132e

import angr

class MagicRATForceHook(angr.SimProcedure):
    NO_RET = True
    def __init__(self, plength=0, project=None, cc=None, prototype=None, symbolic_return=None, returns=None, is_syscall=False, is_stub=False, num_args=None, display_name=None, library_name=None, is_function=None, **kwargs):
        super().__init__(project, cc, prototype, symbolic_return, returns, is_syscall, is_stub, num_args, display_name, library_name, is_function, **kwargs)
        self.plength=plength
        
    def run(self):
        #self.state.solver.add(self.state.regs.ebx == 0)
        #self.state.solver.BVAND(self.state.regs.ebx, self.state.regs.ebx)
        self.state.regs.ebx = 1 # set TEST ebx, ebx to true
        #self.state.inspect.skip_jump = True
        jumpkind = 'Ijk_NoHook' if self.plength == 0 else 'Ijk_Boring'
        print(self.plength)
        self.successors.add_successor(self.state, self.state.addr+self.plength, self.state.solver.true, jumpkind)
        #return   