import os
import sys
import logging
import angr

try:
    lw = logging.getLogger("CustomSimProcedureLinux")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)


class strrchr(angr.SimProcedure):
    # return address of the last occurrence
    def run(self, string, searchedChar):

        if string.symbolic or searchedChar.symbolic:
            return self.state.solver.BVS(
                "retval_{}".format(self.display_name), self.arch.bits
            )
        
        try:
            first_str = self.state.mem[string].string.concrete
            lw.debug("string is concrete")
            lw.debug(first_str)
        except:
            lw.debug("string not resolvable")
            found = False
            for i in range(0x100):
                if self.state.solver.eval(self.state.memory.load(string+i,1)) == 0x0:
                    if i == 0:
                        lw.debug("can't find length")
                        return self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
                    lw.debug("found length")
                    lw.debug(i)
                    first_str = self.state.memory.load(string,i)
                    lw.debug(first_str)
                    found = True
                    break
            if not found:
                lw.debug("can't find length")
                return self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
        
        if hasattr(first_str, "decode"):
            try:
                first_str = first_str.decode("utf-8")
            except:
                first_str = first_str.decode("utf-8",errors="ignore")
        
        lw.debug(first_str)
        searchedChar_conc = chr(self.state.solver.eval(searchedChar))
        lw.debug(searchedChar_conc)
        offset = len(first_str)
        for char in first_str[::-1]:
            if char == searchedChar_conc:
                lw.debug("found char")
                lw.debug(offset)
                return string+offset-1
            offset -= 1

        return string+offset
