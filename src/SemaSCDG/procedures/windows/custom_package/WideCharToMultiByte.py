import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class WideCharToMultiByte(angr.SimProcedure):

    def run(
        self,
        CodePage,
        dwFlags,
        lpWideCharStr,
        cchWideChar,
        lpMultiByteStr,
        cbMultiByte,
        lpDefaultChar,
        lpUsedDefaultChar
    ):
        CodePage = self.state.solver.eval(CodePage)
        cbMultiByte = self.state.solver.eval(cbMultiByte)
        
        try:
            string = self.state.mem[lpWideCharStr].wstring.concrete
        except:
            lw.info("Cannot resolve lpWideCharStr")
            return 0
            
        length = len(string)+1
        if cbMultiByte == 0:
            if CodePage == 0xfdea:
                return length*2
            else:
                return length
        else:
            string = string + "\0"
            if CodePage == 0xfdea:
                self.state.memory.store(lpMultiByteStr,self.state.solver.BVV(string.encode("utf-16le")))
                return length*2
            else:
                self.state.memory.store(lpMultiByteStr,self.state.solver.BVV(string))
                return length

            
            
