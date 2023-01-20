import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class CreateProcessA(angr.SimProcedure):

    def run(
        self,
        lpApplicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation
    ):
        print("prout 0")
        # processinfo = self.state.solver.BVS("Process_Information{}".format(self.display_name), 32*4)
        # self.state.memory.store(lpProcessInformation, processinfo)
        print("prout")
        # print(self.state.regs)
        # print(self.state.regs.eip)
        # print(self.state.regs.esp)
        # ret_addr = self.state.stack_pop() # ret address
        # print(ret_addr)
        # print(self.state.regs.eip)
        # print(self.state.regs.esp)
        # ret_addr = self.state.stack_pop() # args 1
        # print(ret_addr)
        # print(self.state.regs.eip)
        # print(self.state.regs.esp)
        # ret_addr = self.state.stack_pop()
        # print(ret_addr)
        # ret_addr = self.state.stack_pop()
        # print(ret_addr)
        # print(self.state.regs.eip)
        # print(self.state.regs.esp)
        # ret_addr = self.state.stack_pop()
        # print(ret_addr)
        # ret_addr = self.state.stack_pop()
        # print(ret_addr)
        # print(self.state.regs.eip)
        # print(self.state.regs.esp)
        # ret_addr = self.state.stack_pop() # args 6
        # print(ret_addr)
        # print(self.state.regs.eip)
        # print(self.state.regs.esp)
        # ret_addr = self.state.stack_pop()
        # print(ret_addr)
        # print(self.state.regs.eip)
        # print(self.state.regs.esp)
        # ret_addr = self.state.stack_pop()
        # print(ret_addr)
        # print(self.state.regs.eip)
        # print(self.state.regs.esp)
        # ret_addr = self.state.stack_pop()
        # print(ret_addr)
        # print(self.state.regs.eip)
        # print(self.state.regs.esp)
        # ret_addr = self.state.stack_pop() # args 10
        # print(ret_addr)
        # print(self.state.regs.eip)
        # print(self.state.regs.esp)
        
        # ret_addr = self.state.stack_pop()
        # print(ret_addr)
        # print(self.state.regs.eip)
        # print(self.state.regs.esp)
        # self.state.stack_push(ret_addr)
        # # pop edi 
        # esp = self.state.regs.esp
        # edi_value = self.state.memory.load(esp, 4, endness='Iend_LE')
        # self.state.regs.edi = edi_value
        # self.state.regs.esp = esp + 4
        
        # # pop esi 
        # esp = self.state.regs.esp
        # esi_value = self.state.memory.load(esp, 4, endness='Iend_LE')
        # self.state.regs.esi = esi_value
        # self.state.regs.esp = esp + 4
        
        # # pop ebp
        # esp = self.state.regs.esp
        # ebp_value = self.state.memory.load(esp, 4, endness='Iend_LE')
        # self.state.regs.ebp = ebp_value
        # self.state.regs.esp = esp + 4
    
        # # pop ebx
        # esp = self.state.regs.esp
        # ebx_value = self.state.memory.load(esp, 4, endness='Iend_LE')
        # self.state.regs.ebx = ebx_value
        # self.state.regs.esp = esp + 4
        
        # # ADD        ESP,0x368
        # self.state.regs.esp += 0x368
        
        # self.state.stack_push(ret_addr+10) #TODO hardcoded for stromatatck
        
        # self.state.regs.eax = 0x1
        
        # self.state.regs.esp += 4 * 6
        print(self.state.arch.bits)
        return 0x1 # always succeed
        # return self.state.solver.BVV(self.state.regs.esp, self.state.arch.bits)

        # return self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
