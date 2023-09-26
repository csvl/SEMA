import angr

######################################
# free
######################################
class free(angr.SimProcedure):
    # pylint:disable=arguments-differ,unused-argument

    def run(self, ptr):
        print("cool")
        self.state.heap._free(ptr)