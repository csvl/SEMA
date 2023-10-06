import logging
import angr
from angr.sim_options import MEMORY_CHUNK_INDIVIDUAL_READS
from angr.storage.memory_mixins.regioned_memory.abstract_address_descriptor import AbstractAddressDescriptor
lw = logging.getLogger("CustomSimProcedureWindows")

# class strstr(angr.SimProcedure):
#     def strlen(self, s, wchar=False, maxlen=None):
#         if wchar:
#             null_seq = self.state.solver.BVV(0, 16)
#             char_size = 2
#         else:
#             null_seq = self.state.solver.BVV(0, 8)
#             char_size = 1

#         max_symbolic_bytes = self.state.libc.buf_symbolic_bytes
#         max_str_len = self.state.libc.max_str_len
#         if maxlen:
#             max_str_len = min(maxlen, max_str_len)

#         chunk_size = None
#         if MEMORY_CHUNK_INDIVIDUAL_READS in self.state.options:
#             chunk_size = 1

#         if self.state.mode == "static":

#             max_null_index = 0

#             # Make sure to convert s to ValueSet
#             addr_desc: AbstractAddressDescriptor = self.state.memory._normalize_address(s)

#             # size_t
#             length = self.state.solver.ESI(self.arch.bits)
#             for s_aw in self.state.memory._concretize_address_descriptor(addr_desc, None):

#                 s_ptr = s_aw.to_valueset(self.state)
#                 r, c, i = self.state.memory.find(
#                     s,
#                     null_seq,
#                     max_str_len,
#                     max_symbolic_bytes=max_symbolic_bytes,
#                     chunk_size=chunk_size,
#                     char_size=char_size,
#                 )

#                 max_null_index = max([max_null_index] + i)

#                 # Convert r to the same region as s
#                 r_desc = self.state.memory._normalize_address(r)
#                 r_aw_iter = self.state.memory._concretize_address_descriptor(
#                     r_desc, None, target_region=next(iter(s_ptr._model_vsa.regions.keys()))
#                 )

#                 for r_aw in r_aw_iter:
#                     r_ptr = r_aw.to_valueset(self.state)
#                     length = length.union(r_ptr - s_ptr)

#             return length, max_null_index

#         else:
#             search_len = max_str_len
#             r, c, i = self.state.memory.find(
#                 s,
#                 null_seq,
#                 search_len,
#                 max_symbolic_bytes=max_symbolic_bytes,
#                 chunk_size=chunk_size,
#                 char_size=char_size,
#             )

#             # try doubling the search len and searching again
#             s_new = s
#             while c and all(con.is_false() for con in c):
#                 s_new += search_len
#                 search_len *= 2
#                 r, c, i = self.state.memory.find(
#                     s_new,
#                     null_seq,
#                     search_len,
#                     max_symbolic_bytes=max_symbolic_bytes,
#                     chunk_size=chunk_size,
#                     char_size=char_size,
#                 )
#                 # stop searching after some reasonable limit
#                 if search_len > 0x10000:
#                     raise angr.SimMemoryLimitError("strlen hit limit of 0x10000")

#             max_null_index = max(i)
#             self.state.add_constraints(*c)
#             result = r - s
#             if result.depth > 3:
#                 rresult = self.state.solver.BVS("strlen", len(result), key=("api", "strlen"))
#                 self.state.add_constraints(result == rresult)
#                 result = rresult
#             return result, max_null_index
    
#     def run(self, haystack, needle):
#         # Get the haystack and needle strings from the memory
#         if haystack.symbolic or needle.symbolic:
#             return haystack
#         # haystack_strlen = self.inline_call(strlen, haystack) 
#         # needle_strlen = self.inline_call(strlen, needle)
#         # print(haystack_max_null_index)
#         # print(needle_max_null_index)
#         _, haystack_max_null_index = self.strlen(haystack)
#         print(haystack_max_null_index)
#         haystack_str = self.state.memory.load(haystack,size=haystack_max_null_index)
#         print(haystack_str)
        
#         _, needle_max_null_index = self.strlen(needle)
#         needle_str = self.state.memory.load(needle,size=needle_max_null_index)
#         print(needle_max_null_index)
#         print(needle_str)
#         needle_str = self.state.solver.eval(needle_str,cast_to=bytes)
#         print(needle_str)
        
#         if haystack_str.symbolic:
#             print(hex(self.state.solver.eval(self.state.memory.load(haystack,size=haystack_max_null_index))))
#             for i in range(needle_max_null_index):
#                 print(i)
#                 print(hex(needle_str[i]))
#                 self.state.memory.store(haystack+i,needle_str[i],size=1)
#             self.state.memory.store(haystack+haystack_max_null_index,0,size=1)
#             print(haystack)
#             print(haystack_str)
#             print(hex(self.state.solver.eval(self.state.memory.load(haystack,size=haystack_max_null_index))))
#             return haystack
#         haystack_str = self.state.solver.eval(haystack_str,cast_to=bytes)
 
#         # Find the needle in the haystack
#         needle_index = haystack_str.find(needle_str)
#         print(needle_index)
#         if needle_index == -1:
#             return 0
#         else:
#             print(haystack + needle_index)
#             return haystack + needle_index

#     # def run(self, mainstring, substring):

    #     if mainstring.symbolic or substring.symbolic:
    #         return mainstring
        
        
    #     #main_str = self.state.mem[mainstring].string.concrete
    #     sub_str = self.state.mem[substring].string.concrete
    #     chunk_size = None
    #     if MEMORY_CHUNK_INDIVIDUAL_READS in self.state.options:
    #         chunk_size = 1

    #     r, c, i = self.state.memory.find(mainstring, sub_str, 16, max_symbolic_bytes=self.state.libc.max_symbolic_strstr, default=0, chunk_size=chunk_size)
    #     self.state.add_constraints(*c)
    #     lw.info("... returning %s", r)
    #     return r   
        
        
        # if hasattr(main_str, "decode"):
        #     try:
        #         main_str = main_str.decode("utf-8")
        #     except:
        #         main_str = main_str.decode("utf-8",errors="ignore")
        # if hasattr(sub_str, "decode"):
        #     try:
        #         sub_str = sub_str.decode("utf-8")
        #     except:
        #         sub_str = sub_str.decode("utf-8",errors="ignore")
        
        # new_str = main_str + sub_str + "\0"

        # len_s = len(sub_str)
        # src = self.state.memory.load(substring,len_s,endness='Iend_BE')
        # self.state.memory.store(mainstring+len(main_str),src,endness='Iend_BE')

        # self.arguments = [main_str,sub_str]
        # self.ret_expr = main_str
        # return mainstring

class strstr(angr.SimProcedure):
    def strlen(self, s, wchar=False, maxlen=None):
        if wchar:
            null_seq = self.state.solver.BVV(0, 16)
            char_size = 2
        else:
            null_seq = self.state.solver.BVV(0, 8)
            char_size = 1

        max_symbolic_bytes = self.state.libc.buf_symbolic_bytes
        max_str_len = self.state.libc.max_str_len
        if maxlen:
            max_str_len = min(maxlen, max_str_len)

        chunk_size = None
        if MEMORY_CHUNK_INDIVIDUAL_READS in self.state.options:
            chunk_size = 1

        if self.state.mode == "static":

            max_null_index = 0

            # Make sure to convert s to ValueSet
            addr_desc: AbstractAddressDescriptor = self.state.memory._normalize_address(s)

            # size_t
            length = self.state.solver.ESI(self.arch.bits)
            for s_aw in self.state.memory._concretize_address_descriptor(addr_desc, None):

                s_ptr = s_aw.to_valueset(self.state)
                r, c, i = self.state.memory.find(
                    s,
                    null_seq,
                    max_str_len,
                    max_symbolic_bytes=max_symbolic_bytes,
                    chunk_size=chunk_size,
                    char_size=char_size,
                )

                max_null_index = max([max_null_index] + i)

                # Convert r to the same region as s
                r_desc = self.state.memory._normalize_address(r)
                r_aw_iter = self.state.memory._concretize_address_descriptor(
                    r_desc, None, target_region=next(iter(s_ptr._model_vsa.regions.keys()))
                )

                for r_aw in r_aw_iter:
                    r_ptr = r_aw.to_valueset(self.state)
                    length = length.union(r_ptr - s_ptr)

            return length, max_null_index

        else:
            search_len = max_str_len
            r, c, i = self.state.memory.find(
                s,
                null_seq,
                search_len,
                max_symbolic_bytes=max_symbolic_bytes,
                chunk_size=chunk_size,
                char_size=char_size,
            )

            # try doubling the search len and searching again
            s_new = s
            while c and all(con.is_false() for con in c):
                s_new += search_len
                search_len *= 2
                r, c, i = self.state.memory.find(
                    s_new,
                    null_seq,
                    search_len,
                    max_symbolic_bytes=max_symbolic_bytes,
                    chunk_size=chunk_size,
                    char_size=char_size,
                )
                # stop searching after some reasonable limit
                if search_len > 0x10000:
                    raise angr.SimMemoryLimitError("strlen hit limit of 0x10000")

            max_null_index = max(i)
            self.state.add_constraints(*c)
            result = r - s
            if result.depth > 3:
                rresult = self.state.solver.BVS("strlen", len(result), key=("api", "strlen"))
                self.state.add_constraints(result == rresult)
                result = rresult
            return result, max_null_index
   

    def run(self, haystack_addr, needle_addr,haystack_strlen=None, needle_strlen=None):
        # strlen = angr.SIM_PROCEDURES['libc']['strlen']
        strncmp = angr.SIM_PROCEDURES['libc']['strncmp']
        # haystack_strlen = self.inline_call(strlen, haystack_addr) if haystack_strlen is None else haystack_strlen
        # needle_strlen = self.inline_call(strlen, needle_addr) if needle_strlen is None else needle_strlen

        # naive approach
        # haystack_maxlen = haystack_max_null_index
        # needle_maxlen = needle_max_null_index
        _, haystack_max_null_index = self.strlen(haystack_addr)
        needle_strlen_ret_expr, needle_max_null_index = self.strlen(needle_addr)
        lw.info("strstr: " + str(self.arguments))
        lw.info("strstr with size %d haystack and size %d needle...", haystack_max_null_index, needle_max_null_index)

        if needle_max_null_index == 0:
            lw.info("... zero-length needle.")
            return haystack_addr
        elif haystack_max_null_index == 0:
            lw.info("... zero-length haystack.")
            return self.state.solver.BVV(0, self.state.arch.bits)

        if self.state.solver.symbolic(needle_strlen_ret_expr):
            cases = [ [ needle_strlen_ret_expr == 0, haystack_addr ] ]
            exclusions = [ needle_strlen_ret_expr != 0 ]
            remaining_symbolic = self.state.libc.max_symbolic_strstr
            for i in range(haystack_max_null_index):
                lw.info("... case %d (%d symbolic checks remaining)", i, remaining_symbolic)

                # big hack!
                cmp_res = self.inline_call(strncmp, haystack_addr + i, needle_addr, needle_strlen_ret_expr, a_len=haystack_strlen, b_len=needle_strlen)
                c = self.state.solver.And(*([ self.state.solver.UGE(haystack_strlen.ret_expr, needle_strlen_ret_expr), cmp_res.ret_expr == 0 ] + exclusions))
                exclusions.append(cmp_res.ret_expr != 0)

                if self.state.solver.symbolic(c):
                    remaining_symbolic -= 1

                #print "CASE:", c
                cases.append([ c, haystack_addr + i ])
                haystack_strlen.ret_expr = haystack_strlen.ret_expr - 1

                if remaining_symbolic == 0:
                    lw.info("... exhausted remaining symbolic checks.")
                    break

            cases.append([ self.state.solver.And(*exclusions), self.state.solver.BVV(0, self.state.arch.bits) ])
            lw.info("... created %d cases", len(cases))
            r = self.state.solver.ite_cases(cases, 0)
            c = [ self.state.solver.Or(*[c for c,_ in cases]) ]
        else:
            needle_length = self.state.solver.eval(needle_strlen_ret_expr)
            needle_str = self.state.memory.load(needle_addr, needle_length)
            lw.info("... concrete needle of length %d.", needle_length)
            lw.info("... needle: %s", needle_str)
            chunk_size = None
            if MEMORY_CHUNK_INDIVIDUAL_READS in self.state.options:
                chunk_size = 1

            r, c, i = self.state.memory.find(haystack_addr, needle_str, haystack_max_null_index, max_symbolic_bytes=self.state.libc.max_symbolic_strstr, default=0, chunk_size=chunk_size)

        self.state.add_constraints(*c)
        lw.info("... returning %s", r+needle_length)
        return r+needle_length
    
    