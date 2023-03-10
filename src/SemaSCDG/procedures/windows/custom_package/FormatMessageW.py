import logging
import angr
from cle.backends.externs.simdata.io_file import io_file_data_for_arch

lw = logging.getLogger("CustomSimProcedureWindows")


class FormatMessageW(angr.SimProcedure):
    def run(self, dwFlags, lpSource, dwMessageId, dwLanguageId, lpBuffer, nSize, Arguments):
        """_summary_
        Formats a message string. The function requires a message definition as input. The message definition can come from a 
        buffer passed into the function. It can come from a message table resource in an already-loaded module. Or the caller 
        can ask the function to search the system's message table resource(s) for the message definition. The function finds 
        the message definition in a message table resource based on a message identifier and a language identifier. The function 
        copies the formatted message text to an output buffer, processing any embedded insert sequences if requested.
        """
        ptr=self.state.solver.BVS("lpBuffer",8*self.state.solver.eval(nSize))
        self.state.memory.store(lpBuffer,ptr)
        
        addr = self.state.solver.eval(lpSource)
        buf = self.state.solver.eval(lpBuffer)
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
                    try:
                        arg = self.state.mem[argaddr].string.concrete
                        if hasattr(arg, "decode"):
                            arg = arg.decode("utf-8")
                    except:
                        arg = self.state.solver.eval(argaddr)
                        arg = hex(arg) # TODO 
                    sup_args.append(arg)
                    self.state.memory.store(buf,self.state.solver.BVV(arg))
                    buf += len(arg)
                else:
                    self.state.memory.store(buf,self.state.solver.BVV(0x25,8))
                    buf += 1
                    self.state.memory.store(buf,self.state.solver.BVV(byte,8))
                    buf += 1
            elif byte == 0x25: # %
                flag = 1
            else:
                self.state.memory.store(buf,self.state.solver.BVV(byte,8))
                buf += 1
            addr += 1
            byte = self.state.solver.eval(self.state.memory.load(addr,1))
        #self.arguments = self.arguments + sup_args
        
        return self.state.solver.eval(nSize) - 1
