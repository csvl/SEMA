import angr
from angr.sim_type import SimTypeNum 

class GetCurrentThreadId(angr.SimProcedure):
    def run(self):
        return 0xbad76ead
        #returned = SimTypeNum(32, False) #self.state.solver.BVS('retval_{}'.format(self.display_name), 32) # dword
        # returned = self.state.solver.BVS('thread_id', 32)
        # self.state.solver.add(returned.UGE(0))
        # #self.state.solver.add(returned >= 0)
        # return returned
        # TIB_addr = self.state.regs.fs.concat(self.state.solver.BVV(0, 16))
        # return self.state.mem[TIB_addr + 0x24].dword
