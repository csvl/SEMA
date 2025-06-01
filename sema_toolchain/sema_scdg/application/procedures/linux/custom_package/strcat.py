import os
import sys
import logging
import angr

try:
    lw = logging.getLogger("CustomSimProcedureLinux")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)


class strcat(angr.SimProcedure):
    def run(self, string1, string2):
        # strncat = angr.SIM_PROCEDURES["libc"]["strncat"]
        # return self.inline_call(strncat, string1, string2, 0x100000000).ret_expr
        if string1.symbolic or string2.symbolic:
            lw.debug("string1 or string2 symbolic")
            return self.state.solver.BVS(
                "retval_{}".format(self.display_name), self.arch.bits
            )
        
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
                    lw.debug(first_str)
                    found = True
                    break
            if not found:
                lw.debug("can't find length")
                return self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
            

        if string1.symbolic or string2.symbolic:
            return self.state.solver.BVS(
                "retval_{}".format(self.display_name), self.arch.bits
            )
        first_str = self.state.mem[string1].string.concrete
        second_str = self.state.mem[string2].string.concrete
        
        lw.debug(first_str)
        lw.debug(second_str)

        if hasattr(first_str, "decode"):
            try:
                first_str = first_str.decode("utf-8")
            except:
                lw.debug("string1 not decodable")
                #first_str = first_str.decode("utf-8",errors="ignore")
        if hasattr(second_str, "decode"):
            try:
                second_str = second_str.decode("utf-8")
            except:
                lw.debug("string2 not decodable")
                #second_str = second_str.decode("utf-8",errors="ignore")
                pass
        new_str = first_str + second_str + "\0"
        
        lw.debug(first_str)
        lw.debug(second_str)
        
        lw.debug(len(first_str))
        lw.debug(len(second_str))
        
        

        len_s = len(second_str)
        src = self.state.memory.load(string2,len_s) # ,endness='Iend_BE'
        #self.state.memory.store(string1+len(first_str),second_str) # ,endness='Iend_BE'
        self.state.memory.store(string1,new_str)
        
        self.arguments = [first_str,second_str]
        self.ret_expr = first_str
        lw.debug("new_str")
        sol = self.state.mem[string1].string.concrete
        lw.debug(sol)
        lw.debug(len(sol))
        return string1
        
        new_str = first_str + second_str + "\0"

        len_s = len(second_str)
        src = self.state.memory.load(string2,len_s,endness='Iend_BE')
        self.state.memory.store(string1+len(first_str)-1,src,endness='Iend_BE')

        self.arguments = [first_str,second_str]
        self.ret_expr = first_str
        
        lw.debug("new_str")
        lw.debug(self.state.mem[string1].string.concrete)
        return string1
