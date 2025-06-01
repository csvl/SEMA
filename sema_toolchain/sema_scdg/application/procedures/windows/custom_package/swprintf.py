import os
import sys
import logging
import angr

import os

from angr.procedures.libc import wchar

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ.get("LOG_LEVEL", "INFO"))
except Exception as e:
    print(e)


class swprintf(angr.SimProcedure):
    def run(self, arg1, arg2, arg3):
        #mirore of sprintf with minimal change
        lw.debug("swprintf: " + str(self.arguments))

        if self.state.solver.symbolic(arg1) or self.state.solver.symbolic(arg2):
            return self.state.solver.BVS(
                "retval_{}".format(self.display_name), self.arch.bits
            )

        addr = self.state.solver.eval(arg2)
        buf = self.state.solver.eval(arg1)
        wchar = self.state.solver.eval(self.state.memory.load(addr, 2))
        flag = 0
        sup_args = []
        formatcount = 0
        while wchar != 0x0000:
            if flag == 1:
                formatcount += 1
                flag = 0
                if wchar == 0x0064 or wchar == 0x0069:  # %d %i
                    arg = str(self.state.mem[self.state.regs.esp + 8 + 4 * formatcount].int.concrete)
                    sup_args.append(arg)

                    for ch in arg:
                        self.state.memory.store(buf, self.state.solver.BVV(ord(ch), 16))
                        buf += 2

                elif wchar == 0x0073:  # s
                    argaddr = self.state.mem[self.state.regs.esp + 8 + 4 * formatcount].int.concrete
                    try:
                        arg = self.state.mem[argaddr].string.concrete
                        if hasattr(arg, "decode"):
                            arg = arg.decode("utf-8")
                    except:
                        arg = self.state.solver.eval(argaddr)
                        arg = hex(arg)  # TODO
                    sup_args.append(arg)
                    for ch in arg:
                        self.state.memory.store(buf, self.state.solver.BVV(ord(ch), 16))
                        buf += 2

                else:
                    self.state.memory.store(buf, self.state.solver.BVV(0x0025, 16))
                    buf += 2
                    self.state.memory.store(buf, self.state.solver.BVV(wchar, 16))
                    buf += 2
            elif wchar == 0x0025:  # %
                flag = 1
            else:
                self.state.memory.store(buf, self.state.solver.BVV(wchar, 16))
                buf += 2
            addr += 2
            wchar = self.state.solver.eval(self.state.memory.load(addr, 2))
        self.arguments = self.arguments + sup_args
        return buf - self.state.solver.eval(arg1)

