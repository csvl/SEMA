import angr
import claripy

class VarBoolFromStr(angr.SimProcedure):
    def run(self, strIn, lcid, dwFlags, pboolOut):
        # Get the string value
        in_str = self.state.solver.eval(strIn, cast_to=bytes)

        # Parse the string to determine the boolean value
        bool_value = claripy.Bool(in_str.lower() in ["true", "1"])

        # Write the boolean value to the output argument
        self.state.memory.store(pboolOut, bool_value, endness=self.state.arch.memory_endness)

        # Return success
        return 0
