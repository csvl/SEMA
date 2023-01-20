import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class CreateThread(angr.SimProcedure):

    def run(
        self,
        lpThreadAttributes,
        dwStackSize,
        lpStartAddress,
        lpParameter,
        dwCreationFlags,
        lpThreadId
    ):

        #return self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
        
        code_addr = self.state.solver.eval(lpStartAddress)
        ret_addr = self.state.stack_pop()
        self.state.regs.esp += 4 * 6
        new_state = self.state.copy()
        new_state.stack_push(lpParameter)
        new_state.stack_push(ret_addr)
        self.successors.add_successor(new_state, code_addr, new_state.solver.true, 'Ijk_Call')
        self.returns = False
        
        threadId = self.state.solver.BVS("Thread_Id{}".format(self.display_name), self.arch.bits)
        self.state.memory.store(lpThreadId, threadId)
        
        return self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
