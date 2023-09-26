import angr
import claripy
import logging

lw = logging.getLogger('CustomSimProcedureWindows')

class CommandLineToArgvW(angr.SimProcedure):
    def run(self, cmdline_ptr, argc_ptr):
        # Get the size of the command line
        # size = self.state.libc.strlen(cmdline_ptr) + 1
        cmd_str = self.state.mem[cmdline_ptr].wstring.concrete
        lw.info(cmd_str)
        cmd_bytes = cmd_str.encode('utf-16le')
        lw.info(cmd_bytes)
        size = len(cmd_bytes)

        # Allocate memory to store the command line
        buf = self.state.heap.malloc(size)
        self.state.memory.store(buf, cmd_bytes)
        #self.state.libc.memcpy(buf, cmdline_ptr, size)

        # Create a list of argument pointers
        args = []
        arg_ptr = buf
        while self.state.mem[arg_ptr].uint8_t.concrete == 32:  # Skip leading spaces
            arg_ptr += 1
        while self.state.mem[arg_ptr].uint8_t.concrete != 0:
            args.append(arg_ptr)
            while self.state.mem[arg_ptr].uint8_t.concrete not in [32, 0]:  # Skip non-space characters
                arg_ptr += 1
            while self.state.mem[arg_ptr].uint8_t.concrete == 32:  # Skip spaces
                arg_ptr += 1
        args.append(0)

        # Write argc
        self.state.mem[argc_ptr].int32_t = len(args) - 1

        # Allocate space for argv
        argv_ptr = self.state.heap.malloc(len(args) * self.state.arch.bytes)

        # Write the argument pointers
        for i, arg in enumerate(args):
            arg_val = claripy.BVV(arg, self.state.arch.bits)
            #self.state.mem[argv_ptr + i * self.state.arch.bytes].int32_t = arg_val
            lw.info(arg_val)
            self.state.memory.store(argv_ptr + i * self.state.arch.bytes, arg_val)

        # Return argv
        return argv_ptr
