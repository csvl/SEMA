import logging
import angr

lw = logging.getLogger("CustomSimProcedureLinux")

class strrchr(angr.SimProcedure):
    # return address of the last occurrence
    def run(self, string, searchedChar):

        if string.symbolic or searchedChar.symbolic:
            return self.state.solver.BVS(
                "retval_{}".format(self.display_name), self.arch.bits
            )
        
        try:
            first_str = self.state.mem[string].string.concrete
            lw.info("string is concrete")
            lw.info(first_str)
        except:
            lw.info("string not resolvable")
            found = False
            for i in range(0x100):
                if self.state.solver.eval(self.state.memory.load(string+i,1)) == 0x0:
                    if i == 0:
                        lw.info("can't find length")
                        return self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
                    lw.info("found length")
                    lw.info(i)
                    first_str = self.state.memory.load(string,i)
                    lw.info(first_str)
                    found = True
                    break
            if not found:
                lw.info("can't find length")
                return self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
        
        if hasattr(first_str, "decode"):
            try:
                first_str = first_str.decode("utf-8")
            except:
                first_str = first_str.decode("utf-8",errors="ignore")
        
        lw.info(first_str)
        searchedChar_conc = chr(self.state.solver.eval(searchedChar))
        lw.info(searchedChar_conc)
        offset = len(first_str)
        for char in first_str[::-1]:
            if char == searchedChar_conc:
                lw.info("found char")
                lw.info(offset)
                return string+offset-1
            offset -= 1

        return string+offset
