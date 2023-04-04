import angr
import claripy

class GetUserDefaultLCID(angr.SimProcedure):
    def run(self):
        # Return value of the function
        #ret_type = claripy.BVS('ret', self.state.arch.bits)

        # Call to the Windows API function
        # lcid = self.inline_call(
        #     self.state.libc.gets,
        #     claripy.BVV('UserDefaultLCID\n\0', 16)
        # ).ret

        # Convert the result to an integer
        lcid_int = 0x0409 #int(lcid)

        # # Set the return value
        # self.state.memory.store(
        #     self.arg(0),
            
        # )
        # self.state.globals['last_error'] = 0
        return claripy.BVV(lcid_int, self.state.arch.bits)
