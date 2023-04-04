import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class CreateRemoteThread(angr.SimProcedure):

    def run(
        self,
        hProcess,
        lpThreadAttributes,
        dwStackSize,
        lpStartAddress,
        lpParameter,
        dwCreationFlags,
        lpThreadId
    ):
        
        if not self.state.globals["is_thread"]:
            # code_addr = self.state.solver.eval(lpStartAddress)
            lw.info("IS THREAD")
            lw.info(self.state.solver.eval(lpStartAddress))
            #self.state.regs.esp += 4 * 6
            import pdb 
            #pdb.set_trace()
            new_state = self.state.copy()
            _ = new_state.stack_pop()
            new_state.stack_push(0xdeadbeef)
            # new_state.stack_push(lpThreadId)
            # new_state.stack_push(dwCreationFlags)
            # new_state.stack_push(lpParameter)
            # new_state.stack_push(lpStartAddress)
            # new_state.stack_push(dwStackSize)
            # new_state.stack_push(lpThreadAttributes)
            # new_state.stack_push(hProcess)
            # new_state.stack_push(0xdeadbeef)
            #pdb.set_trace()
            self.state.globals["create_thread_address"].append(
                {
                    "new_state":new_state
                }
            )
            # self.state.regs.esp -= 4 * 6
            return self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
        else:
            lw.info("IS NOT THREAD")
            lw.info(self.state.solver.eval(lpStartAddress))
            code_addr = self.state.solver.eval(lpStartAddress)
            ret_addr  = self.state.stack_pop()
            lw.info(ret_addr)
            self.state.regs.esp += 4 * 6 #7
            new_state = self.state.copy()
            new_state.stack_push(lpParameter)
            new_state.stack_push(ret_addr)
            self.successors.add_successor(new_state, code_addr, new_state.solver.true, 'Ijk_Call')
            self.returns = False
            
            threadId = self.state.solver.BVS("Thread_Id{}".format(self.display_name),  self.arch.bits)
            self.state.memory.store(lpThreadId, threadId)
            
            return self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
