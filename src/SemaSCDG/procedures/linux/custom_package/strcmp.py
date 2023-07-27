import logging
import angr

lw = logging.getLogger("CustomSimProcedureLinux")


class strcmp(angr.SimProcedure):
    def run(self, string1, string2):
        if string1.symbolic or string2.symbolic:
            return self.state.solver.BVS("retval_{}".format(self.display_name), 32)
            
        try:
            first_str = self.state.mem[string1].string.concrete
            lw.info("string1 is concrete")
            lw.info(first_str)
        except:
            lw.info("string1 not resolvable")
            found = False
            for i in range(0x100):
                if self.state.solver.eval(self.state.memory.load(string1+i,1)) == 0x0:
                    if i == 0:
                        lw.info("can't find length")
                        return self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
                    lw.info("found length")
                    lw.info(i)
                    first_str = self.state.memory.load(string1,i)
                    lw.info(first_str)
                    found = True
            if not found:
                lw.info("can't find length")
                return self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
        try:
            second_str = self.state.mem[string2].string.concrete
            lw.info("string2 is concrete")
            lw.info(second_str)
        except:
            lw.info("string2 not resolvable")
            found = False
            for i in range(0x100):
                if self.state.solver.eval(self.state.memory.load(string2+i,1)) == 0x0:
                    if i == 0:
                        lw.info("can't find length")
                        return self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
                    lw.info("found length")
                    lw.info(i)
                    second_str = self.state.memory.load(string2,i)
            if not found:
                lw.info("can't find length")
                return self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
            
        try:
            first_str = first_str.decode("utf-8")
        except:
            lw.info("string1 not decodable")
            first_str = first_str.decode("utf-8",errors="ignore")
        try:
            second_str = second_str.decode("utf-8")
        except:
            lw.info("string2 not decodable")
            second_str = second_str.decode("utf-8",errors="ignore")
            
        lw.info(first_str)
        lw.info(second_str)
        if first_str == second_str:
            lw.info("strings are equal")
            return 0
        elif first_str > second_str:
            lw.info("string1 is greater than string2")
            
            return 1
        else:
            lw.info("string1 is less than string2")
            return -1
