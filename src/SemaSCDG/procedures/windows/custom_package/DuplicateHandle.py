import angr
import claripy
import copy

class DuplicateHandle(angr.SimProcedure):
    def run(self, hSourceProcessHandle, hSourceHandle, hTargetProcessHandle, lpTargetHandle, dwDesiredAccess, bInheritHandle, dwOptions):
        self.state.memory.store(lpTargetHandle, self.state.solver.eval(hSourceHandle), self.arch.bits)
        #lpTargetHandle = copy.deepcopy(lpTargetHandle) # TODO
        ret_val = self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
        #self.state.solver.add(ret_val > 0)
        return 0x1
        #return self.state.solver.BVV("retval_{}".format(self.display_name), self.arch.bits)