import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class lstrcpyW(angr.SimProcedure):
    def run(self, lpstring1, lpstring2):
        if lpstring1.symbolic or lpstring2.symbolic:
            return lpstring1
            
        try:
            second_str = self.state.mem[lpstring2].wstring.concrete
        except:
            lw.info("lpstring2 not resolvable")
            second_str = ""
            
        new_str = second_str + "\0"
        new_str = self.state.solver.BVV(new_str.encode("utf-16le"))
        self.state.memory.store(lpstring1, new_str)
        return lpstring1
