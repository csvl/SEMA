import angr
import claripy

class GetFileVersionInfoSizeW(angr.SimProcedure):
    def run(self, lptstrFilename, lpdwHandle):
        # Treat lptstrFilename as a concrete value or a symbolic variable of type LPCWSTR
        if self.state.solver.symbolic(lptstrFilename):
            lptstrFilename = self.state.solver.Unconstrained("lptstrFilename", 8 * 260)
        # Treat lpdwHandle as a concrete value or a symbolic variable of type LPDWORD
        if self.state.solver.symbolic(lpdwHandle):
            lpdwHandle = self.state.solver.Unconstrained("lpdwHandle", self.state.arch.bits)
        # Set the value of lpdwHandle to a non-zero value to indicate success
        # self.state.memory.store(lpdwHandle, self.state.solver.BVV(1, self.state.arch.bits))
        # Return a symbolic value of type UINT # x20 #
        # dwLen = self.state.solver.BVS("dwLen{}".format(self.display_name),self.state.arch.bits)
        # self.state.solver.add(dwLen >= 1)
        # self.state.solver.add(dwLen <= 128)
        
        # lpdata
        # typedef struct {
        # WORD             wLength;
        # WORD             wValueLength;
        # WORD             wType;
        # WCHAR            szKey;
        # WORD             Padding1;
        # VS_FIXEDFILEINFO Value;
        # WORD             Padding2;
        # WORD             Children;
        # } VS_VERSIONINFO;
        
        word_size = 2
        dword_size = 4
        VS_FIXEDFILEINFO_size = dword_size*13 
        return VS_FIXEDFILEINFO_size + 6*word_size + len("VS_VERSION_INFO".encode("utf-16-le"))
