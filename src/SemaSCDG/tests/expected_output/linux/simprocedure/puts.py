import angr
import logging

lw = logging.getLogger("LinuxSimProcedure")

class puts(angr.SimProcedure):
    def run(self, string_addr):
        # string_addr: address of the null-terminated string
        
        lw.info("puts")

        # Use the state's memory to read the string from the specified address
        string = str(self.state.mem[string_addr].string.concrete)

        # Perform the puts operation (write the string to the standard output)
        # Note: This is a simple example, and the actual implementation
        # would depend on the specifics of your binary and the operating system
        # simfd = self.state.posix.get_fd(1)
        # simfd.write(string, len(string))

        # Append a newline character to simulate the behavior of puts
        newline = '\n\0'
        # simfd.write(newline, len(newline))
        
        new_str = string + newline
        #new_str = new_str.decode("utf-8")
        lw.info("new_str: " + new_str)
        new_str = self.state.solver.BVV(new_str)
        # self.state.memory.store(string_addr, new_str)

        # Return the number of characters written (optional)
        return len(string) + len(newline) - 1
