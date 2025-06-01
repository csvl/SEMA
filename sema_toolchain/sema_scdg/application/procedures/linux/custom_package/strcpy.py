import os
import sys
import logging
import angr
from angr.sim_options import MEMORY_CHUNK_INDIVIDUAL_READS
from angr.storage.memory_mixins.regioned_memory.abstract_address_descriptor import AbstractAddressDescriptor

try:
    lw = logging.getLogger("CustomSimProcedureLinux")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)



class strcpy(angr.SimProcedure):
    def run(self, lpstring1, lpstring2):
        if lpstring1.symbolic or lpstring2.symbolic:
            lw.debug("lpstring1 or lpstring2 symbolic")
            return lpstring1
            
        try:
            second_str = self.state.mem[lpstring2].string.concrete
            lw.debug("second_str: " + str(second_str))
        except:
            lw.debug("lpstring2 not resolvable")
            found = False
            for i in range(0x100):
                if self.state.solver.eval(self.state.memory.load(lpstring2+i,1)) == 0x0:
                    if i == 0:
                        lw.debug("can't find length")
                        return self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
                    lw.debug("found length")
                    lw.debug(i)
                    second_str = self.state.memory.load(lpstring2,i)
            if not found:
                lw.debug("can't find length")
                return self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
            
        try:
            second_str = second_str.decode("utf-8")
        except:
            lw.debug("string2 not decodable")
            second_str = second_str.decode("utf-8",errors="ignore")
            
        new_str = second_str + "\0"
        #new_str = self.state.solver.BVV(new_str)
        
        self.state.memory.store(lpstring1, new_str)
        
        lw.debug("new_str")
        sol = self.state.mem[lpstring1].string.concrete
        lw.debug(sol)
        lw.debug(len(sol))
        lw.debug("new_str: " + str(new_str))
        return lpstring1