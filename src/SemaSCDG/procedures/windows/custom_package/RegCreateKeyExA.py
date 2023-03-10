import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class RegCreateKeyExA(angr.SimProcedure):

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
        return 0x0
