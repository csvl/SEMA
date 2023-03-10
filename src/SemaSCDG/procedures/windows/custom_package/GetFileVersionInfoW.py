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
        
        # lpdata
        # typedef struct {
        # WORD             wLength;
        # WORD             wValueLength;
        # WORD             wType;
        # WCHAR            szKey; # len("VS_VERSION_INFO")
        # WORD             Padding1;
        # VS_FIXEDFILEINFO Value;
        # WORD             Padding2;
        # WORD             Children;
        # } VS_VERSIONINFO;
        
        word_size = 2
        dword_size = 4
        VS_FIXEDFILEINFO_size = dword_size*13 
        
        VS_VERSIONINFO = {
            'wLength': VS_FIXEDFILEINFO_size + 6*word_size + len("VS_VERSION_INFO".encode("utf-16-le")), # 0xFEEF04BD,
            'wValueLength': VS_FIXEDFILEINFO_size, # 0xFEEF04BD,
            'wType': self.state.solver.BVS("wType{}".format(self.display_name),16), # 0xFEEF04BD,
            'szKey': "VS_VERSION_INFO".encode("utf-16-le"), # 0xFEEF04BD,
            'Padding1': self.state.solver.BVS("Children{}".format(self.display_name),16), # 0xFEEF04BD,
            'Padding2': self.state.solver.BVS("Children{}".format(self.display_name),16), # 0xFEEF04BD,
            'Children': self.state.solver.BVS("Children{}".format(self.display_name),16), # 0xFEEF04BD,
        }
        
        VS_FIXEDFILEINFO = {
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
        lplpBuffer_addr = self.state.solver.eval(lpData)
        
        self.state.mem[lplpBuffer_addr].word = VS_VERSIONINFO['wLength']
        self.state.mem[lplpBuffer_addr + word_size].word = VS_VERSIONINFO['wValueLength']
        self.state.mem[lplpBuffer_addr + word_size*2].word = VS_VERSIONINFO['wType']
        self.state.memory.store(lplpBuffer_addr + word_size*3, VS_VERSIONINFO['szKey'])
        #self.state.mem[lplpBuffer_addr + word_size*3].wstring = VS_VERSIONINFO['szKey']
        
        self.state.solver.add(VS_VERSIONINFO['Padding1'] == 0)
        
        self.state.mem[lplpBuffer_addr + word_size*3 + len("VS_VERSION_INFO".encode("utf-16-le"))].word = VS_VERSIONINFO['Padding1']
        
        self.state.mem[lplpBuffer_addr + word_size*4 + len("VS_VERSION_INFO".encode("utf-16-le"))].dword = VS_FIXEDFILEINFO['dwSignature']
        self.state.mem[lplpBuffer_addr + word_size*4 + len("VS_VERSION_INFO".encode("utf-16-le")) + dword_size].dword = VS_FIXEDFILEINFO['dwStrucVersion']
        self.state.mem[lplpBuffer_addr + word_size*4 + len("VS_VERSION_INFO".encode("utf-16-le")) + dword_size*2].dword = VS_FIXEDFILEINFO['dwFileVersionMS']
        self.state.mem[lplpBuffer_addr + word_size*4 + len("VS_VERSION_INFO".encode("utf-16-le")) + dword_size*3].dword = VS_FIXEDFILEINFO['dwFileVersionLS']
        self.state.mem[lplpBuffer_addr + word_size*4 + len("VS_VERSION_INFO".encode("utf-16-le")) + dword_size*4].dword = VS_FIXEDFILEINFO['dwProductVersionMS']
        self.state.mem[lplpBuffer_addr + word_size*4 + len("VS_VERSION_INFO".encode("utf-16-le")) + dword_size*5].dword = VS_FIXEDFILEINFO['dwProductVersionLS']
        self.state.mem[lplpBuffer_addr + word_size*4 + len("VS_VERSION_INFO".encode("utf-16-le")) + dword_size*6].dword = VS_FIXEDFILEINFO['dwFileFlagsMask']
        self.state.mem[lplpBuffer_addr + word_size*4 + len("VS_VERSION_INFO".encode("utf-16-le")) + dword_size*7].dword = VS_FIXEDFILEINFO['dwFileFlags']
        self.state.mem[lplpBuffer_addr + word_size*4 + len("VS_VERSION_INFO".encode("utf-16-le")) + dword_size*8].dword = VS_FIXEDFILEINFO['dwFileOS']
        self.state.mem[lplpBuffer_addr + word_size*4 + len("VS_VERSION_INFO".encode("utf-16-le")) + dword_size*9].dword = VS_FIXEDFILEINFO['dwFileType']
        self.state.mem[lplpBuffer_addr + word_size*4 + len("VS_VERSION_INFO".encode("utf-16-le")) + dword_size*10].dword = VS_FIXEDFILEINFO['dwFileSubtype']
        self.state.mem[lplpBuffer_addr + word_size*4 + len("VS_VERSION_INFO".encode("utf-16-le")) + dword_size*11].dword = VS_FIXEDFILEINFO['dwFileDateMS']
        self.state.mem[lplpBuffer_addr + word_size*4 + len("VS_VERSION_INFO".encode("utf-16-le")) + dword_size*12].dword = VS_FIXEDFILEINFO['dwFileDateLS']
        
        self.state.solver.add(VS_VERSIONINFO['Padding2'] == 0)
        self.state.mem[lplpBuffer_addr + word_size*4 + len("VS_VERSION_INFO".encode("utf-16-le")) + dword_size*13].word = VS_VERSIONINFO['Padding2']
        self.state.mem[lplpBuffer_addr + word_size*5 + len("VS_VERSION_INFO".encode("utf-16-le")) + dword_size*13].word = VS_VERSIONINFO['Children']
       
            
        return 0x1 #self.state.solver.Unconstrained("bResult", 8)
