import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
import logging

try:
    logger = logging.getLogger("SCDGDebugger")
    logger.propagate = False
    logger.setLevel(logging.DEBUG)
except Exception as e:
    print(e)
    print("Error: config file not found")

class Debugger():

    def __init__(self):
        self.log = logger


    # Break at specific instruction and open debug mode.
    def debug_instr(self, state):
        if state.inspect.instruction == int(
            "0x0040123f", 16
        ) or state.inspect.instruction == int("0x0040126e", 16):
            self.log.info("Debug function\n\n")
            self.log.info(hex(state.inspect.instruction))
            import pdb

            pdb.set_trace()

    def debug_read(self, state):
        if state.solver.eval(state.inspect.mem_read_address) == int("0xf404120", 16):
            self.log.info("Read function\n\n")
            self.log.info(state.inspect.mem_read_address)
            import pdb

            pdb.set_trace()

    def debug_write(self, state):
        if state.solver.eval(state.inspect.mem_write_address) == int("0xf404120", 16):
            self.log.info("Write function\n\n")
            self.log.info(state.inspect.mem_write_address)
            import pdb

            pdb.set_trace()
