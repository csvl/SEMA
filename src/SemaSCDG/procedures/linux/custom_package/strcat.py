import logging
import angr

lw = logging.getLogger("CustomSimProcedureLinux")


class strcat(angr.SimProcedure):
    def run(self, string1, string2):
        # strncat = angr.SIM_PROCEDURES["libc"]["strncat"]
        # return self.inline_call(strncat, string1, string2, 0x100000000).ret_expr
        if string1.symbolic or string2.symbolic:
            lw.info("string1 or string2 symbolic")
            return self.state.solver.BVS(
                "retval_{}".format(self.display_name), self.arch.bits
            )
        
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
                    break
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
                    lw.info(first_str)
                    found = True
                    break
            if not found:
                lw.info("can't find length")
                return self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
            

        if string1.symbolic or string2.symbolic:
            return self.state.solver.BVS(
                "retval_{}".format(self.display_name), self.arch.bits
            )
        first_str = self.state.mem[string1].string.concrete
        second_str = self.state.mem[string2].string.concrete
        
        lw.info(first_str)
        lw.info(second_str)

        if hasattr(first_str, "decode"):
            try:
                first_str = first_str.decode("utf-8")
            except:
                lw.info("string1 not decodable")
                #first_str = first_str.decode("utf-8",errors="ignore")
        if hasattr(second_str, "decode"):
            try:
                second_str = second_str.decode("utf-8")
            except:
                lw.info("string2 not decodable")
                #second_str = second_str.decode("utf-8",errors="ignore")
                pass
        new_str = first_str + second_str + "\0"
        
        lw.info(first_str)
        lw.info(second_str)
        
        lw.info(len(first_str))
        lw.info(len(second_str))
        
        

        len_s = len(second_str)
        src = self.state.memory.load(string2,len_s) # ,endness='Iend_BE'
        #self.state.memory.store(string1+len(first_str),second_str) # ,endness='Iend_BE'
        self.state.memory.store(string1,new_str)
        
        self.arguments = [first_str,second_str]
        self.ret_expr = first_str
        lw.info("new_str")
        sol = self.state.mem[string1].string.concrete
        lw.info(sol)
        lw.info(len(sol))
        return string1
        
        new_str = first_str + second_str + "\0"

        len_s = len(second_str)
        src = self.state.memory.load(string2,len_s,endness='Iend_BE')
        self.state.memory.store(string1+len(first_str)-1,src,endness='Iend_BE')

        self.arguments = [first_str,second_str]
        self.ret_expr = first_str
        
        lw.info("new_str")
        lw.info(self.state.mem[string1].string.concrete)
        return string1
