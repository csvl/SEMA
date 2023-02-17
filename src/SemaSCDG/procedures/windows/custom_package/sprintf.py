import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")

# class sprintf(angr.SimProcedure):
#     def run(self, buffer, format, args):
#         # Get the format string
#         strlen = angr.SIM_PROCEDURES['libc']['strlen']
#         format_strlen = self.inline_call(strlen, format) 

#         format_str = self.state.memory.load(format, size=format_strlen.max_null_index, endness='Iend_LE')
#         format_str = self.state.solver.eval(format_str) # ,cast_to=bytes
#         print(format_str)
#         # Get the number of arguments
#         num_args = len(format_str.split("%") ) -1 
#         # Get the arguments
#         arg_list = []
#         for i in range(num_args):
#             arg = self.state.memory.load(args + i* self.arch.bytes, self.arch.bytes)
#             arg = self.state.solver.eval(arg)
#             arg_list.append(arg)
#         # format the arguments with the format string
#         formatted_string = format_str.format(*arg_list)
#         # Write the formatted string to the buffer
#         self.state.memory.store(buffer, formatted_string.encode())
#         # return the number of characters written to the buffer
#         return len(formatted_string)

class sprintf(angr.SimProcedure):
    def getVarString(self, ptr):
        string = self.state.mem[ptr].string.concrete
        if hasattr(string, "decode"):
            string = string.decode("utf-8")
        return string

    def run(self, arg1, arg2):

        # import pdb; pdb.set_trace()
        lw.info("sprintf: " + str(self.arguments))

        if arg1.symbolic or arg2.symbolic:
            return self.state.solver.BVS(
                "retval_{}".format(self.display_name), self.arch.bits
            )
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
        self.arguments = self.arguments + sup_args
        return buf - self.state.solver.eval(arg1)

# import logging

# from angr.procedures.stubs.format_parser import FormatParser

# # l = logging.getLogger(name=__name__)

# ######################################
# # sprintf
# ######################################


# class sprintf(FormatParser):

#     # pylint:disable=arguments-differ

#     def run(self, dst_ptr, fmt):  # pylint:disable=unused-argument , args1, args2
#         # The format str is at index 1
#         fmt_str = self._parse(fmt)
#         lw.info("sprintf: " + str(self.arguments))
#         lw.info("sprintf: " + str(fmt_str))
#         out_str = fmt_str.replace(self.va_arg)
#         self.state.memory.store(dst_ptr, out_str)

#         # place the terminating null byte
#         self.state.memory.store(
#             dst_ptr + (out_str.size() // self.arch.byte_width), self.state.solver.BVV(0, self.arch.byte_width)
#         )

#         return out_str.size() // self.arch.byte_width