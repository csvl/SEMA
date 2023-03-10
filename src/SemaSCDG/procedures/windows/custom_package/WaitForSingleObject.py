import angr
import claripy

class WaitForSingleObject(angr.SimProcedure):
    def run(self, hHandle, dwMilliseconds):

        # Treat hHandle as an unconstrained symbolic variable of type HANDLE
        # hHandle = self.state.solver.Unconstrained("hHandle", self.state.arch.bits)

        # Constrain dwMilliseconds to be non-negative
        self.state.add_constraints(dwMilliseconds >= 0)
        
        # Return WAIT_OBJECT_0 to indicate that the object is signaled
        return  self.state.solver.BVS(
                "retval_{}".format(self.display_name), self.arch.bits
            ) # 0x00000001 #self.state.solver.BVV(angr.sim_type.SimTypeLength.from_arch(self.state.arch).size, 0)
