import os
import sys
import logging
import angr

try:
    lw = logging.getLogger("CustomSimProcedureLinux")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)


class strcmp(angr.SimProcedure):
    def run(self, string1, string2):
        
        if string1.symbolic or string2.symbolic:
            return self.state.solver.BVS("retval_{}".format(self.display_name), 32)

        try:
            first_str = self.state.mem[string1].string.concrete
            lw.debug("string1 is concrete")
            lw.debug(first_str)
        except:
            lw.debug("string1 not resolvable")
            found = False
            for i in range(0x100):
                if self.state.solver.eval(self.state.memory.load(string1+i,1)) == 0x0:
                    if i == 0:
                        lw.debug("can't find length")
                        return self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
                    lw.debug("found length")
                    lw.debug(i)
                    first_str = self.state.memory.load(string1,i)
                    lw.debug(first_str)
                    found = True
                    break
            if not found:
                lw.debug("can't find length")
                return self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
        try:
            second_str = self.state.mem[string2].string.concrete
            lw.debug("string2 is concrete")
            lw.debug(second_str)
        except:
            lw.debug("string2 not resolvable")
            found = False
            for i in range(0x100):
                if self.state.solver.eval(self.state.memory.load(string2+i,1)) == 0x0:
                    if i == 0:
                        lw.debug("can't find length")
                        return self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
                    lw.debug("found length")
                    lw.debug(i)
                    second_str = self.state.memory.load(string2,i)
            if not found:
                lw.debug("can't find length")
                return self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)

        try:
            first_str = first_str.decode("utf-8")
        except:
            lw.debug("string1 not decodable")
            #first_str = first_str.decode("utf-8",errors="ignore")
        try:
            second_str = second_str.decode("utf-8")
        except:
            lw.debug("string2 not decodable")
            #second_str = second_str.decode("utf-8",errors="ignore")
        lw.debug(repr(first_str))
        lw.debug(repr(second_str))

        if first_str == second_str:
            lw.debug("strings are equal")
            return 0
        elif first_str > second_str:
            lw.debug("string1 is greater than string2")

            return 1
        else:
            lw.debug("string1 is less than string2")
            return -1