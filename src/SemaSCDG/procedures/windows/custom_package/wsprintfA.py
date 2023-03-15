import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class wsprintfA(angr.SimProcedure):
    def getVarString(self, ptr):
        string = self.state.mem[ptr].string.concrete
        if hasattr(string, "decode"):
            string = string.decode("utf-8")
        return string

    def run(self, arg1, arg2):

        lw.info("wsprintfA: " + str(self.arguments))

        if arg1.symbolic or arg2.symbolic:
            return self.state.solver.BVS(
                "retval_{}".format(self.display_name), self.arch.bits
            )
        
        addr = self.state.solver.eval(arg2)
        buf = self.state.solver.eval(arg1)
        byte = self.state.solver.eval(self.state.memory.load(addr,1))
        flag = 0
        sup_args = []
        formatcount = 0
        while(byte != 0x0):
            if flag == 1:
                formatcount += 1
                flag = 0
                if byte == 0x64 or byte == 0x69: #%d %i
                    arg = str(self.state.mem[self.state.regs.esp + 8 + 4 * formatcount].int.concrete)
                    sup_args.append(arg)
                    self.state.memory.store(buf,self.state.solver.BVV(arg))
                    buf += len(arg)
                elif byte == 0x73: #s
                    argaddr = self.state.mem[self.state.regs.esp + 8 + 4 * formatcount].int.concrete
                    arg = self.state.mem[argaddr].string.concrete.decode("utf-8")
                    sup_args.append(arg)
                    self.state.memory.store(buf,self.state.solver.BVV(arg))
                    buf += len(arg)
                else:
                    self.state.memory.store(buf,self.state.solver.BVV(0x25,8))
                    buf += 1
                    self.state.memory.store(buf,self.state.solver.BVV(byte,8))
                    buf += 1
            elif byte == 0x25:
                flag = 1
            else:
                self.state.memory.store(buf,self.state.solver.BVV(byte,8))
                buf += 1
            addr += 1
            byte = self.state.solver.eval(self.state.memory.load(addr,1))
        self.arguments = self.arguments + sup_args
        return buf - self.state.solver.eval(arg1)
        
        # var_string = self.getVarString(arg2)
        # n_arg = var_string.count("%")
        # sup_args = []
        # for i in range(1, n_arg + 1):
        #     sup_args.append(
        #         self.state.mem[self.state.regs.esp + 8 + 4 * i].int.resolved
        #     )
        #     # import pdb; pdb.set_trace()
        # self.arguments = self.arguments + sup_args
        # new_str = self.state.solver.BVV(var_string)
        # self.state.memory.store(arg1, new_str)
        # # import pdb; pdb.set_trace()

        # return len(var_string)
