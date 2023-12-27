import angr
import logging

lw = logging.getLogger("CustomSimProcedureLinux")

class strtok(angr.SimProcedure):
    """_summary_
    The strtok_r() method splits str[] according to given delimiters and returns the next token. 
    It needs to be called in a loop to get all tokens. It returns NULL when there are no more tokens.
    strtok_r() does the same task of parsing a string into a sequence of tokens. 
    strtok_r() is a reentrant version of strtok(), hence it is thread safe.
    Args:
        angr (_type_): _description_
    """
    def run(self, str_ptr, delim_ptr):
        lw.info('^'*100)
        lw.info('using strtok')
        strtok_arr = self.state.globals.get('strtok', self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits))
"""
strtok_r = self.state.globals.get('strtok', self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits))
"""
        # Get the memory objects representing the strings
        # str_object = self.state.memory.load(str_ptr)
        # delim_object = self.state.memory.load(delim_ptr)

        # Get the actual strings from the memory objects
        str_data = self.state.mem[str_ptr].string.concrete # self.state.solver.eval(str_object, cast_to=bytes).decode()
        delim_data = self.state.mem[delim_ptr].string.concrete # self.state.solver.eval(delim_object, cast_to=bytes).decode()

        if len(strtok_arr) == 0:

          #if len(strtok_r) == 0:
            self.state.globals["strtok"] = [[False, elem] for elem in str_data.split(delim_data)]
        else:
            for elem in self.state.globals["strtok"]:
                if not elem[0]:
                    lw.info(elem)
                    elem[0] = True
                    dest_ptr = str_ptr
                    token_data = elem[1].decode("utf-8") + "\x00"
                    token_size = len(token_data) 

                    lw.info(f"token_data: {token_data}")
                    lw.info(f"token_size: {token_size}")

                    self.state.memory.store(dest_ptr, token_data)
                    lw.info(strtok_arr)
                    lw.info('^'*100)
                    return dest_ptr
            
            self.state.globals["strtok"] = []
            lw.info(strtok_arr)
            lw.info('^'*100)
""""
                    lw.info("token_data")
                    lw.info(token_data)
                    lw.info("token_size")
                    lw.info(token_size)
                    self.state.memory.store(dest_ptr, token_data)
                    #self.state.memory.store(dest_ptr + token_size, self.state.solver.BVV(0, 8))  # Null terminator
                    return dest_ptr
                    #break
"""
            return 0x0
                    
# class strtok(angr.SimProcedure):
#     """_summary_
#     The strtok() method splits str[] according to given delimiters and returns the next token. 
#     It needs to be called in a loop to get all tokens. It returns NULL when there are no more tokens.
#     Args:
#         angr (_type_): _description_
#     """
#     def run(self, str_ptr, delim_ptr):
#         # Get the memory objects representing the strings
#         try: 
#             str_object = self.state.mem[str_ptr].string.concrete
#         except:
#             found = False
#             for i in range(0x100):
#                 if self.state.solver.eval(self.state.memory.load(str_ptr+i,1)) == 0x0:
#                     if i == 0:
#                         lw.info("can't find length")
#                         return self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
#                     lw.info("found length")
#                     lw.info(i)
#                     str_object = self.state.memory.load(str_ptr,i)
#                     lw.info(str_object)
#                     found = True
#                     break
#             if not found:
#                 return self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
        
#         delim_object = self.state.mem[delim_ptr].string.concrete # self.state.memory.load(delim_ptr)

#         # Get the actual strings from the memory objects
#         # str_data = self.state.solver.eval(str_object, cast_to=bytes).decode()
#         # delim_data = self.state.solver.eval(delim_object, cast_to=bytes).decode()

#         str_data = str_object.decode()
#         delim_data = delim_object.decode()
        
        
#         # Find the starting position of the next token
#         start_pos = 0

#         # Find the end position of the token
#         end_pos = start_pos
#         while end_pos < len(str_data) and str_data[end_pos] not in delim_data:
#             end_pos += 1

#         # Create the token
#         token_data = str_data[start_pos:end_pos]
#         lw.info("token_data")
#         lw.info(token_data)
#         token_size = len(token_data) + 1  # Include the null terminator

#         # Update the strtok internal state (store the start_pos for the next call)
#         # strtok_state = self.state.solver.BVS('strtok_state', self.arch.bits)
#         # self.state.add_constraints(strtok_state == end_pos)

#         # Store the token in the destination buffer (simulating strtok behavior)
#         dest_ptr = str_ptr
#         self.state.memory.store(dest_ptr, self.state.solver.BVV(token_data.encode()))
#         self.state.memory.store(dest_ptr + token_size, self.state.solver.BVV(0, 8))  # Null terminator

#         return dest_ptr