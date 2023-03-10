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
        
        word_size = 2
        dword_size = 4
        VS_FIXEDFILEINFO_size = dword_size*13 
        
        # check if we're retrieving the root block
        if sub_block_str == '':
            # get the VS_FIXEDFILEINFO structure
            # fixed_file_info_offset = angr.state_plugins.SimDLLS.state_fastsim.file_handle_to_offset[pBlock_addr]
            # fixed_file_info_struct = angr.state_plugins.SimDLLS.state_fastsim.memory.pack_bits(angr.state_plugins.SimDLLS.state_fastsim.memory.read_bytes(fixed_file_info_offset, 52))
            # self.state.memory.store(lplpBuffer_addr, fixed_file_info_struct)
            # self.state.memory.store(puLen_addr, claripy.BVV(52, 32))
            # structure = {
            #     'dwSignature': self.state.mem[pBlock_addr + word_size*4 + len("VS_VERSION_INFO".encode("utf-16-le"))].dword, # 0xFEEF04BD,
            #     'dwStrucVersion': self.state.mem[pBlock_addr + word_size*4 + len("VS_VERSION_INFO".encode("utf-16-le")) + dword_size].dword , # 0x00010000,
            #     'dwFileVersionMS': self.state.mem[pBlock_addr + word_size*4 + len("VS_VERSION_INFO".encode("utf-16-le")) + dword_size*2].dword, # 0x00030001,
            #     'dwFileVersionLS': self.state.mem[pBlock_addr + word_size*4 + len("VS_VERSION_INFO".encode("utf-16-le")) + dword_size*3].dword, #  0x00040001,
            #     'dwProductVersionMS': self.state.mem[pBlock_addr + word_size*4 + len("VS_VERSION_INFO".encode("utf-16-le")) + dword_size*4].dword, # 0x00030002,
            #     'dwProductVersionLS': self.state.mem[pBlock_addr + word_size*4 + len("VS_VERSION_INFO".encode("utf-16-le")) + dword_size*5].dword, # 0x00040002,
            #     'dwFileFlagsMask': self.state.mem[pBlock_addr + word_size*4 + len("VS_VERSION_INFO".encode("utf-16-le")) + dword_size*6].dword, # 0x0000003F,
            #     'dwFileFlags': self.state.mem[pBlock_addr + word_size*4 + len("VS_VERSION_INFO".encode("utf-16-le")) + dword_size*7].dword, # 0x00000001,
            #     'dwFileOS': self.state.mem[pBlock_addr + word_size*4 + len("VS_VERSION_INFO".encode("utf-16-le")) + dword_size*8].dword, # 0x00000004,
            #     'dwFileType': self.state.mem[pBlock_addr + word_size*4 + len("VS_VERSION_INFO".encode("utf-16-le")) + dword_size*9].dword, # 0x00000001,
            #     'dwFileSubtype': self.state.mem[pBlock_addr + word_size*4 + len("VS_VERSION_INFO".encode("utf-16-le")) + dword_size*10].dword, # 0x00000000,
            #     'dwFileDateMS':self.state.mem[pBlock_addr + word_size*4 + len("VS_VERSION_INFO".encode("utf-16-le")) + dword_size*11].dword, #  0x00000000,
            #     'dwFileDateLS':self.state.mem[pBlock_addr + word_size*4 + len("VS_VERSION_INFO".encode("utf-16-le")) + dword_size*12].dword, #  0x00000000
            # }
            structure = {
                'dwSignature': self.state.memory.load(pBlock_addr + word_size*4 + len("VS_VERSION_INFO".encode("utf-16-le")),size=4), # 0xFEEF04BD,
                'dwStrucVersion': self.state.memory.load(pBlock_addr + word_size*4 + len("VS_VERSION_INFO".encode("utf-16-le")) + dword_size,size=4) , # 0x00010000,
                'dwFileVersionMS': self.state.memory.load(pBlock_addr + word_size*4 + len("VS_VERSION_INFO".encode("utf-16-le")) + dword_size*2,size=4), # 0x00030001,
                'dwFileVersionLS': self.state.memory.load(pBlock_addr + word_size*4 + len("VS_VERSION_INFO".encode("utf-16-le")) + dword_size*3,size=4), #  0x00040001,
                'dwProductVersionMS': self.state.memory.load(pBlock_addr + word_size*4 + len("VS_VERSION_INFO".encode("utf-16-le")) + dword_size*4,size=4), # 0x00030002,
                'dwProductVersionLS': self.state.memory.load(pBlock_addr + word_size*4 + len("VS_VERSION_INFO".encode("utf-16-le")) + dword_size*5,size=4), # 0x00040002,
                'dwFileFlagsMask': self.state.memory.load(pBlock_addr + word_size*4 + len("VS_VERSION_INFO".encode("utf-16-le")) + dword_size*6,size=4), # 0x0000003F,
                'dwFileFlags': self.state.memory.load(pBlock_addr + word_size*4 + len("VS_VERSION_INFO".encode("utf-16-le")) + dword_size*7,size=4), # 0x00000001,
                'dwFileOS': self.state.memory.load(pBlock_addr + word_size*4 + len("VS_VERSION_INFO".encode("utf-16-le")) + dword_size*8,size=4), # 0x00000004,
                'dwFileType': self.state.memory.load(pBlock_addr + word_size*4 + len("VS_VERSION_INFO".encode("utf-16-le")) + dword_size*9,size=4), # 0x00000001,
                'dwFileSubtype': self.state.memory.load(pBlock_addr + word_size*4 + len("VS_VERSION_INFO".encode("utf-16-le")) + dword_size*10,size=4), # 0x00000000,
                'dwFileDateMS':self.state.memory.load(pBlock_addr + word_size*4 + len("VS_VERSION_INFO".encode("utf-16-le")) + dword_size*11,size=4), #  0x00000000,
                'dwFileDateLS':self.state.memory.load(pBlock_addr + word_size*4 + len("VS_VERSION_INFO".encode("utf-16-le")) + dword_size*12,size=4), #  0x00000000
            }
            # Write the structure to memory
            # self.state.memory.store(lplpBuffer_addr, self.state.solver.BVV(structure['dwSignature'], self.state.arch.bits))
            # self.state.memory.store(lplpBuffer_addr + dword_size, self.state.solver.BVV(structure['dwStrucVersion'], self.state.arch.bits))
            # self.state.memory.store(lplpBuffer_addr + dword_size*2, self.state.solver.BVV(structure['dwFileVersionMS'], self.state.arch.bits))
            # self.state.memory.store(lplpBuffer_addr + dword_size*3, self.state.solver.BVV(structure['dwFileVersionLS'], self.state.arch.bits))
            # self.state.memory.store(lplpBuffer_addr + dword_size*4, self.state.solver.BVV(structure['dwProductVersionMS'], self.state.arch.bits))
            # self.state.memory.store(lplpBuffer_addr + dword_size*5, self.state.solver.BVV(structure['dwProductVersionLS'], self.state.arch.bits))
            # self.state.memory.store(lplpBuffer_addr + dword_size*6, self.state.solver.BVV(structure['dwFileFlagsMask'], self.state.arch.bits))
            # self.state.memory.store(lplpBuffer_addr + dword_size*7, self.state.solver.BVV(structure['dwFileFlags'], self.state.arch.bits))
            # self.state.memory.store(lplpBuffer_addr + dword_size*8, self.state.solver.BVV(structure['dwFileOS'], self.state.arch.bits))
            # self.state.memory.store(lplpBuffer_addr + dword_size*9, self.state.solver.BVV(structure['dwFileType'], self.state.arch.bits))
            # self.state.memory.store(lplpBuffer_addr + dword_size*10, self.state.solver.BVV(structure['dwFileSubtype'], self.state.arch.bits))
            # self.state.memory.store(lplpBuffer_addr + dword_size*11, self.state.solver.BVV(structure['dwFileDateMS'], self.state.arch.bits))
            # self.state.memory.store(lplpBuffer_addr + dword_size*12, self.state.solver.BVV(structure['dwFileDateLS'], self.state.arch.bits))
           
            self.state.memory.store(lplpBuffer_addr,                 structure['dwSignature'])
            self.state.memory.store(lplpBuffer_addr + dword_size,    structure['dwStrucVersion'])
            self.state.memory.store(lplpBuffer_addr + dword_size*2,  structure['dwFileVersionMS'])
            self.state.memory.store(lplpBuffer_addr + dword_size*3,  structure['dwFileVersionLS'])
            self.state.memory.store(lplpBuffer_addr + dword_size*4,  structure['dwProductVersionMS'])
            self.state.memory.store(lplpBuffer_addr + dword_size*5,  structure['dwProductVersionLS'])
            self.state.memory.store(lplpBuffer_addr + dword_size*6,  structure['dwFileFlagsMask'])
            self.state.memory.store(lplpBuffer_addr + dword_size*7,  structure['dwFileFlags'])
            self.state.memory.store(lplpBuffer_addr + dword_size*8,  structure['dwFileOS'])
            self.state.memory.store(lplpBuffer_addr + dword_size*9,  structure['dwFileType'])
            self.state.memory.store(lplpBuffer_addr + dword_size*10, structure['dwFileSubtype'])
            self.state.memory.store(lplpBuffer_addr + dword_size*11, structure['dwFileDateMS'])
            self.state.memory.store(lplpBuffer_addr + dword_size*12, structure['dwFileDateLS'])
            # self.state.memory.store(puLen_addr, dword_size*12)
            
            # self.state.mem[lplpBuffer_addr].dword = structure['dwSignature']
            # self.state.mem[lplpBuffer_addr + dword_size].dword = structure['dwStrucVersion']
            # self.state.mem[lplpBuffer_addr + dword_size*2].dword = structure['dwFileVersionMS']
            # self.state.mem[lplpBuffer_addr + dword_size*3].dword = structure['dwFileVersionLS']
            # self.state.mem[lplpBuffer_addr + dword_size*4].dword = structure['dwProductVersionMS']
            # self.state.mem[lplpBuffer_addr + dword_size*5].dword = structure['dwProductVersionLS']
            # self.state.mem[lplpBuffer_addr + dword_size*6].dword = structure['dwFileFlagsMask']
            # self.state.mem[lplpBuffer_addr + dword_size*7].dword = structure['dwFileFlags']
            # self.state.mem[lplpBuffer_addr + dword_size*8].dword = structure['dwFileOS']
            # self.state.mem[lplpBuffer_addr + dword_size*9].dword = structure['dwFileType']
            # self.state.mem[lplpBuffer_addr + dword_size*10].dword = structure['dwFileSubtype']
            # self.state.mem[lplpBuffer_addr + dword_size*11].dword = structure['dwFileDateMS']
            # self.state.mem[lplpBuffer_addr + dword_size*12].dword = structure['dwFileDateLS']
            
            self.state.mem[puLen_addr].dword = dword_size*13
            
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
            # string_table = {}
            # for i in range(0, 0xffff):
            #     # read the length of the string key
            #     key_len_offset = string_table_offset + 2 * i
            #     key_len = self.state.memory.load(key_len_offset, 2, endness='Iend_LE')

            #     if key_len == 0:
            #         break

            #     # read the string key
            #     key_offset = key_len_offset + 2
            #     key = self.state.mem[key_offset:key_offset+2*key_len].string()

            #     # read the length of the string value
            #     value_len_offset = key_offset + 2 * key_len
            #     value_len = self.state.memory.load(value_len_offset, 2, endness='Iend_LE')

            #     # read the string value
            #     # value_offset =
