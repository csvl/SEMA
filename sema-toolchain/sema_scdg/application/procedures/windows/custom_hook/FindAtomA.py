import angr
import claripy
import logging
import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])

# Searches the local atom table for the specified character string and retrieves the atom associated with that string.
# If the function succeeds, the return value is the atom associated with the given string.
# If the function fails, the return value is zero. To get extended error information, call GetLastError.

class FindAtomA(angr.SimProcedure):
    def run(self, lpString):
        if not self.state.has_plugin("plugin_atom"):
            lw.warning("The procedure FindAtomA is using the plugin plugin_atom which is not activated")
        else :
            # self.state.memory.store(lpString, claripy.BVS("WIN32_FIND_DATA", 8 * 320))
            # ret_expr = claripy.BVS("handle_first_file", 32)
            return 0 if lpString not in self.state.plugin_atom.atoms else self.state.plugin_atom.atoms[lpString]
