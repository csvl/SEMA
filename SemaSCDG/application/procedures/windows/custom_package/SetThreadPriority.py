import angr

class SetThreadPriority(angr.SimProcedure):
    def run(self, hThread, dwPriority):
        # Do nothing, just return success
        return 0x1
