import angr
import archinfo
import logging

l = logging.getLogger("CustomSimProcedureWindows")
class RegQueryValueExW(angr.SimProcedure):
    def run(self, hKey, lpValueName, lpReserved, lpType, lpData, lpcbData):
        # The actual implementation of RegQueryValueExW would involve interacting with the Windows
        # registry to retrieve the value of a given key. However, in this simulation, we can simply
        # return a dummy value to represent the result of the function.
        # l.info(self.state.memory.load(lpcbData, 4))
        # l.info(self.state.memory.load(lpcbData, 4, endness=archinfo.Endness.LE))
        return 1