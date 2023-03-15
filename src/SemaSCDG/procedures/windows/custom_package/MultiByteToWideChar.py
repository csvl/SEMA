import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")

class MultiByteToWideChar(angr.SimProcedure):

    def run(
        self,
        CodePage,
        dwFlags,
        lpMultiByteStr,
        cbMultiByte,
        lpWideCharStr,
        cchWideChar
    ):
        CodePage = self.state.solver.eval(CodePage)
        cchWideChar = self.state.solver.eval(cchWideChar)
        
        if CodePage == 0xfdea:
            try:
                string = self.state.mem[lpMultiByteStr].wstring.concrete
            except:
                lw.info("Cannot resolve lpMultiByteStr")
                return 0
        else:
            try:
                string = self.state.mem[lpMultiByteStr].string.concrete
                string = string.decode("utf-8")
            except:
                lw.info("Cannot resolve lpMultiByteStr")
                return 0
        
        length = len(string) + 1
        if cchWideChar == 0:
            return length
        else:
            string = string + "\0"
            self.state.memory.store(lpWideCharStr,self.state.solver.BVV(string.encode("utf-16le")))
            return length
