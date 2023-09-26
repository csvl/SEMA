import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class lstrcmpA(angr.SimProcedure):
    def run(self, string1, string2):
        if string1.symbolic or string2.symbolic:
            return self.state.solver.BVS("retval_{}".format(self.display_name), 32)
            
        try:
            first_str = self.state.mem[string1].string.concrete
        except:
            lw.info("string1 not resolvable")
            first_str = ""
        try:
            second_str = self.state.mem[string2].string.concrete
        except:
            lw.info("string2 not resolvable")
            second_str = ""
            
        try:
            first_str = first_str.decode("utf-8")
        except:
            lw.info("string1 not decodable")
            first_str = ""
        try:
            second_str = second_str.decode("utf-8")
        except:
            lw.info("string2 not decodable")
            second_str = ""
            
        if first_str == second_str:
            return 0
        elif first_str > second_str:
            return 1
        else:
            return -1
