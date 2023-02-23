import angr

class __iob_func(angr.SimProcedure):
    def run(self):
        # return a pointer to the array of FILE descriptors
        # self.state.posix.fd 
        return self.state.solver.BVV(0, self.state.arch.bits) # self.state.posix.get_fd(0) #self.state.solver.BVV(0, self.state.arch.bits)