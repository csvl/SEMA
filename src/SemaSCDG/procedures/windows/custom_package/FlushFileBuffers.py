import angr

class FlushFileBuffers(angr.SimProcedure):
    def run(self, handle):
        # Simulate successful return
        return 1
