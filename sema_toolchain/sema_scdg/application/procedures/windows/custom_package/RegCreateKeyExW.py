import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
import logging
import angr

import os

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)


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

        # if hKey in self.state.plugin_registry.registry and lpSubKey in self.state.plugin_registry.registry[hKey]:
        #     return 0x0

        # self.state.memory.store(self.state.plugin_registry.registry_block, lpLCData)

        # if lpSubKey not in self.state.plugin_registry.registry[hKey]:
        #     self.state.plugin_registry.registry[hKey][lpSubKey] = {}
        # else:
        #     self.state.plugin_registry.registry[hKey][lpSubKey] = (LCType, lpLCData, cchData)

        return 0x0
