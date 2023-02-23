import angr
import claripy

# class VerQueryValueW(angr.SimProcedure):
#     def run(self, pBlock, lpSubBlock, lplpBuffer, puLen):
#         # Treat lpSubBlock as a concrete value or a symbolic variable of type LPCWSTR
#         if self.state.solver.symbolic(lpSubBlock):
#             lpSubBlock = self.state.solver.Unconstrained("lpSubBlock", 8 * 260)
#         # Treat puLen as a concrete value or a symbolic variable of type PUINT
#         if self.state.solver.symbolic(puLen):
#             puLen = self.state.solver.Unconstrained("puLen", 8 * 4)
#         # Allocate memory for the output buffer lplpBuffer
#         output_buffer = self.state.solver.BVS("output_buffer", 8 * 1024)
#         # Treat lplpBuffer as a pointer to a memory region of size *puLen
#         if self.state.solver.symbolic(lplpBuffer):
#             self.state.memory.store(lplpBuffer, output_buffer)
#             self.state.memory.store(puLen, 1024)
#         else:
#             self.state.memory.store(lplpBuffer, output_buffer)
#         # Return a symbolic value of type UINT
#         return 0x1 #self.state.solver.Unconstrained("uResult", self.state.arch.bits)

# TODO link more with  GetFileVersionInfoSize function, and then the GetFileVersionInfo function.
class VerQueryValueW(angr.SimProcedure):
    def run(self, pBlock, lpSubBlock, lplpBuffer, puLen):
        # retrieve the values of the arguments
        pBlock_addr = self.state.solver.eval(pBlock)
        lpSubBlock_addr = self.state.solver.eval(lpSubBlock)
        lplpBuffer_addr = self.state.solver.eval(lplpBuffer)
        puLen_addr = self.state.solver.eval(puLen)

        # read the memory pointed to by lpSubBlock
        sub_block_str = self.state.mem[lpSubBlock_addr].wstring.concrete.strip('\\')

        # check if we're retrieving the root block
        if sub_block_str == '':
            # get the VS_FIXEDFILEINFO structure
            # fixed_file_info_offset = angr.state_plugins.SimDLLS.state_fastsim.file_handle_to_offset[pBlock_addr]
            # fixed_file_info_struct = angr.state_plugins.SimDLLS.state_fastsim.memory.pack_bits(angr.state_plugins.SimDLLS.state_fastsim.memory.read_bytes(fixed_file_info_offset, 52))
            # self.state.memory.store(lplpBuffer_addr, fixed_file_info_struct)
            # self.state.memory.store(puLen_addr, claripy.BVV(52, 32))
            structure = {
                'dwSignature': 0xFEEF04BD,
                'dwStrucVersion': 0x00010000,
                'dwFileVersionMS': 0x00030001,
                'dwFileVersionLS': 0x00040001,
                'dwProductVersionMS': 0x00030002,
                'dwProductVersionLS': 0x00040002,
                'dwFileFlagsMask': 0x0000003F,
                'dwFileFlags': 0x00000001,
                'dwFileOS': 0x00000004,
                'dwFileType': 0x00000001,
                'dwFileSubtype': 0x00000000,
                'dwFileDateMS': 0x00000000,
                'dwFileDateLS': 0x00000000
            }
            
            dword_size = 4 if self.state.arch.bits == 32 else 8 # bytes

            # Write the structure to memory
            self.state.memory.store(lplpBuffer_addr, self.state.solver.BVV(structure['dwSignature'], self.state.arch.bits))
            self.state.memory.store(lplpBuffer_addr + dword_size, self.state.solver.BVV(structure['dwStrucVersion'], self.state.arch.bits))
            self.state.memory.store(lplpBuffer_addr + dword_size*2, self.state.solver.BVV(structure['dwFileVersionMS'], self.state.arch.bits))
            self.state.memory.store(lplpBuffer_addr + dword_size*3, self.state.solver.BVV(structure['dwFileVersionLS'], self.state.arch.bits))
            self.state.memory.store(lplpBuffer_addr + dword_size*4, self.state.solver.BVV(structure['dwProductVersionMS'], self.state.arch.bits))
            self.state.memory.store(lplpBuffer_addr + dword_size*5, self.state.solver.BVV(structure['dwProductVersionLS'], self.state.arch.bits))
            self.state.memory.store(lplpBuffer_addr + dword_size*6, self.state.solver.BVV(structure['dwFileFlagsMask'], self.state.arch.bits))
            self.state.memory.store(lplpBuffer_addr + dword_size*7, self.state.solver.BVV(structure['dwFileFlags'], self.state.arch.bits))
            self.state.memory.store(lplpBuffer_addr + dword_size*8, self.state.solver.BVV(structure['dwFileOS'], self.state.arch.bits))
            self.state.memory.store(lplpBuffer_addr + dword_size*9, self.state.solver.BVV(structure['dwFileType'], self.state.arch.bits))
            self.state.memory.store(lplpBuffer_addr + dword_size*10, self.state.solver.BVV(structure['dwFileSubtype'], self.state.arch.bits))
            self.state.memory.store(lplpBuffer_addr + dword_size*11, self.state.solver.BVV(structure['dwFileDateMS'], self.state.arch.bits))
            self.state.memory.store(lplpBuffer_addr + dword_size*12, self.state.solver.BVV(structure['dwFileDateLS'], self.state.arch.bits))
            self.state.memory.store(puLen_addr, dword_size*13)
            return 0x1

        # check if we're retrieving the translation array
        if sub_block_str == 'VarFileInfo\\Translation':
            # get the translation array
            # translation_array_offset = angr.state_plugins.SimDLLS.state_fastsim.file_handle_to_offset[pBlock_addr] + 52
            # translation_array_struct = angr.state_plugins.SimDLLS.state_fastsim.memory.pack_bits(angr.state_plugins.SimDLLS.state_fastsim.memory.read_bytes(translation_array_offset, 4))
            # self.state.memory.store(lplpBuffer_addr, translation_array_struct)
            # self.state.memory.store(puLen_addr, claripy.BVV(4, 32))
            return 0x0

        # check if we're retrieving a value from a language-specific StringTable structure
        if sub_block_str.startswith('StringFileInfo\\'):
            # lang_codepage_str, string_name = sub_block_str[len('StringFileInfo\\'):].split('\\', 1)
            # lang_codepage = tuple(int(lang_codepage_str[i:i+2], 16) for i in range(0, len(lang_codepage_str), 2))

            # get the StringTable structure
            #string_table_offset = angr.state_plugins.SimDLLS.state_fastsim.get_version_string_table_offset(pBlock_addr, lang_codepage)
            #if string_table_offset is None:
            return 0x0

            # get the string value
            string_table = {}
            for i in range(0, 0xffff):
                # read the length of the string key
                key_len_offset = string_table_offset + 2 * i
                key_len = self.state.memory.load(key_len_offset, 2, endness='Iend_LE')

                if key_len == 0:
                    break

                # read the string key
                key_offset = key_len_offset + 2
                key = self.state.mem[key_offset:key_offset+2*key_len].string()

                # read the length of the string value
                value_len_offset = key_offset + 2 * key_len
                value_len = self.state.memory.load(value_len_offset, 2, endness='Iend_LE')

                # read the string value
                # value_offset =
