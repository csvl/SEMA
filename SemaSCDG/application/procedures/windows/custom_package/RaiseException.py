import angr
import logging

lw = logging.getLogger("CustomSimProcedureWindows")

class RaiseException(angr.SimProcedure):
    # Defining a function called "NO_RET" that does not return anything.
    NO_RET = True
    def run(self, hKey, lpValueName, lpReserved, lpType, lpData, lpcbData):
        # Implement the logic for querying the value of a registry key using the provided parameters.
        lw.info("RaiseException called")
        return 