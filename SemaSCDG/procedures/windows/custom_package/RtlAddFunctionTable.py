import angr

class RtlAddFunctionTable(angr.SimProcedure):
    def run(self, pFunctionTable, dwEntryCount, dwBaseAddress):
        # We can just return STATUS_SUCCESS (0) as the simulated return value
        return 0
