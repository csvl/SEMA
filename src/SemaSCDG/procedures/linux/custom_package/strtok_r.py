import angr
import logging 

lw = logging.getLogger("CustomSimProcedureLinux")

class strtok_r(angr.SimProcedure):
    """_summary_
    The strtok_r() method splits str[] according to given delimiters and returns the next token. 
    It needs to be called in a loop to get all tokens. It returns NULL when there are no more tokens.
    strtok_r() does the same task of parsing a string into a sequence of tokens. 
    strtok_r() is a reentrant version of strtok(), hence it is thread safe.
    Args:
        angr (_type_): _description_
    """
    def run(self, str_ptr, delim_ptr, saveptr):
        strtok_r = self.state.globals.get('strtok_r', self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits))
        # Get the memory objects representing the strings
        # str_object = self.state.memory.load(str_ptr)
        # delim_object = self.state.memory.load(delim_ptr)

        # Get the actual strings from the memory objects
        str_data = self.state.mem[str_ptr].string.concrete # self.state.solver.eval(str_object, cast_to=bytes).decode()
        delim_data = self.state.mem[delim_ptr].string.concrete # self.state.solver.eval(delim_object, cast_to=bytes).decode()

        if len(strtok_r) == 0:
            self.state.globals["strtok_r"] = [[False, elem] for elem in str_data.split(delim_data)]
        else:
            for elem in self.state.globals["strtok_r"]:
                if not elem[0]:
                    print(elem)
                    elem[0] = True
                    dest_ptr = str_ptr
                    token_data = elem[1].decode("utf-8") + "\x00"
                    token_size = len(token_data) 
                    lw.info("token_data")
                    lw.info(token_data)
                    lw.info("token_size")
                    lw.info(token_size)
                    self.state.memory.store(dest_ptr, token_data)
                    #self.state.memory.store(dest_ptr + token_size, self.state.solver.BVV(0, 8))  # Null terminator
                    return dest_ptr
                    #break
            return 0x0
      
        # # Find the starting position of the next token
        # start_pos = self.state.solver.BVS('strtok_start_pos', self.arch.bits)
        # self.state.add_constraints(start_pos >= 0)
        # if self.state.solver.eval(start_pos == 0):
        #     start_pos = self.state.solver.BVV(0, self.arch.bits)

        # # Find the end position of the token
        # end_pos = start_pos
        # while end_pos < len(str_data) and str_data[end_pos] not in delim_data:
        #     end_pos += 1

        # # Create the token
        # token_data = str_data[start_pos:end_pos]
        # token_size = len(token_data) + 1  # Include the null terminator

        # # Update the strtok internal state (store the start_pos for the next call)
        # strtok_state = self.state.solver.BVS('strtok_state', self.arch.bits)
        # self.state.add_constraints(strtok_state == end_pos)

        # # Store the token in the destination buffer (simulating strtok behavior)
        # dest_ptr = str_ptr
        # self.state.memory.store(dest_ptr, self.state.solver.BVV(token_data.encode()))
        # self.state.memory.store(dest_ptr + token_size, self.state.solver.BVV(0, 8))  # Null terminator

        # return dest_ptr