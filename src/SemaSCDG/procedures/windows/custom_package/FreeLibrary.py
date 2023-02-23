import angr

class FreeLibrary(angr.SimProcedure):
    def run(self, h_module):
        # Return 1 on success
        return 1
