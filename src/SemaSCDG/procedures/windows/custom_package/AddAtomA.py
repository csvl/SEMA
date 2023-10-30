import angr
import claripy


# Adds a character string to the local atom table and returns a unique value (an atom) identifying the string.
# If the function succeeds, the return value is the newly created atom.
# If the function fails, the return value is zero. To get extended error information, call GetLastError.
# TODO
class AddAtomA(angr.SimProcedure):
    def run(self, lpString):
        # self.state.memory.store(lpString, claripy.BVS("WIN32_FIND_DATA", 8 * 320))
        # ret_expr = claripy.BVS("handle_first_file", 32)
        self.state.plugin_atom.atoms[lpString] = claripy.BVS("atom", self.arch.bits)
        return 0 if lpString not in self.state.plugin_atom.atoms else self.state.plugin_atom.atoms[lpString]
