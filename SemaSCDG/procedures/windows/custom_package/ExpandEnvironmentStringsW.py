import angr


class ExpandEnvironmentStringsW(angr.SimProcedure):
    def run(self, lpSrc, lpDst, nSize):
        try:
            src = self.state.mem[lpSrc].wstring.concrete
        except:
            lw.info("lpSrc not resolvable")
            lpDst = lpSrc
            return nSize
            
        src.replace("%ProgramFiles%","C:\\Program Files")
        src.replace("%windir%", "C:\\Windows")
        l = len(src)
        src = src + "\0"
        dst = self.state.solver.BVV(src.encode("utf-16le"))
        self.state.memory.store(lpDst, dst)
        return l+1
