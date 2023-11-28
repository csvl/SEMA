import angr
import claripy
import logging

lw = logging.getLogger("LinuxSimProcedure")
class putc(angr.SimProcedure):
    def run(self, fd, char):
        # fd: file descriptor
        # char: character to write

        # You may want to perform additional checks on fd or char if needed
        # ...
        lw.info("putc")
        # Use the state's solver to convert the character to a bitvector
        char_bv = self.state.solver.eval(char, cast_to=bytes)

        # Perform the putc operation (write character to the file descriptor)
        # Note: This is a simple example, and the actual implementation
        # would depend on the specifics of your binary and the operating system
        self.state.posix.write(fd, char_bv, 1)

        # Return the character that was written (optional)
        return char
