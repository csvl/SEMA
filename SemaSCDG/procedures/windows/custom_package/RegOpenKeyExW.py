import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class RegOpenKeyExW(angr.SimProcedure):

    def run(
        self,
        hKey,
        lpSubKey,
        ulOptions,
        samDesired,
        phkResult
    ):
        ptr = self.state.solver.BVS(
            "key_handle_{}".format(self.display_name), self.arch.bits
        )
        self.state.memory.store(phkResult,ptr)
        return 0x0
