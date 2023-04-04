import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class RegCreateKeyExW(angr.SimProcedure):

    def run(
        self,
        hKey,
        lpSubKey,
        Reserved,
        lpClass,
        dwOptions,
        samDesired,
        lpSecurityAttributes,
        phkResult,
        lpdwDisposition
    ):
        ptr = self.state.solver.BVS(
            "key_handle_{}".format(self.display_name), self.arch.bits
        )
        self.state.memory.store(phkResult,ptr)
        
        # if hKey in self.state.plugin_registery.registery and lpSubKey in self.state.plugin_registery.registery[hKey]:
        #     return 0x0
        
        # self.state.memory.store(self.state.plugin_registery.registery_block, lpLCData)  
        
        # if lpSubKey not in self.state.plugin_registery.registery[hKey]:
        #     self.state.plugin_registery.registery[hKey][lpSubKey] = {}
        # else:
        #     self.state.plugin_registery.registery[hKey][lpSubKey] = (LCType, lpLCData, cchData)
        
        return 0x0
