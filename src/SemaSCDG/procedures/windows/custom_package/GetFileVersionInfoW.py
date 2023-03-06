import angr
import claripy

class GetFileVersionInfoW(angr.SimProcedure):
    def run(self, lptstrFilename, dwHandle, dwLen, lpData):
        # Treat lptstrFilename as a concrete value or a symbolic variable of type LPCWSTR
        if self.state.solver.symbolic(lptstrFilename):
            lptstrFilename = self.state.solver.Unconstrained("lptstrFilename", 8 * 260)
        # Treat dwLen as a concrete value or a symbolic variable of type DWORD
        if self.state.solver.symbolic(dwLen):
            dwLen = self.state.solver.Unconstrained("dwLen", self.state.arch.bits)
        # Return a symbolic value of type BOOL
        
        structure = {
                'dwSignature': self.state.solver.BVS("dwSignature{}".format(self.display_name),32), # 0xFEEF04BD,
                'dwStrucVersion': self.state.solver.BVS("dwStrucVersion{}".format(self.display_name),32), # 0x00010000,
                'dwFileVersionMS': self.state.solver.BVS("dwFileVersionMS{}".format(self.display_name),32), # 0x00030001,
                'dwFileVersionLS': self.state.solver.BVS("dwFileVersionLS{}".format(self.display_name),32), #  0x00040001,
                'dwProductVersionMS': self.state.solver.BVS("dwProductVersionMS{}".format(self.display_name),32), # 0x00030002,
                'dwProductVersionLS': self.state.solver.BVS("dwProductVersionLS{}".format(self.display_name),32), # 0x00040002,
                'dwFileFlagsMask': self.state.solver.BVS("dwFileFlagsMask{}".format(self.display_name),32), # 0x0000003F,
                'dwFileFlags': self.state.solver.BVS("dwFileFlags{}".format(self.display_name),32), # 0x00000001,
                'dwFileOS': self.state.solver.BVS("dwFileOS{}".format(self.display_name),32), # 0x00000004,
                'dwFileType': self.state.solver.BVS("dwFileType{}".format(self.display_name),32), # 0x00000001,
                'dwFileSubtype': self.state.solver.BVS("dwFileSubtype{}".format(self.display_name),32), # 0x00000000,
                'dwFileDateMS':self.state.solver.BVS("dwFileDateMS{}".format(self.display_name),32), #  0x00000000,
                'dwFileDateLS': self.state.solver.BVS("dwFileDateLS{}".format(self.display_name),32), #  0x00000000
        }
        dword_size = 4 # if self.state.arch.bits == 32 else 8 # bytes
        lplpBuffer_addr = self.state.solver.eval(lpData)
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
            
       
            
        return 0x1 #self.state.solver.Unconstrained("bResult", 8)
